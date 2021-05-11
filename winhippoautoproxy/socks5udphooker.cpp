// Very bad thing I didn't want to write. Assumes little-endian.

#include <cstdint>
#include <stdio.h>

#include <winsock2.h>
#include <Windows.h>

#include <detours.h>

#define SOCK_BUFLEN 8096
#define LOCALHOST 0x0100007f

// Make sure we hook the functions in winsock2 specifically
HMODULE hLib = LoadLibrary("ws2_32.dll");

typedef int (WSAAPI *RecvFromPtr)(
    SOCKET s,
    char FAR* buf,
    int len,
    int flags,
    struct sockaddr FAR* from,
    int FAR* fromlen
);
static RecvFromPtr sRealRecvFrom = (RecvFromPtr)GetProcAddress(hLib, "recvfrom");
typedef int (WSAAPI* SendToPtr)(
    SOCKET s,
    const char FAR* buf,
    int len,
    int flags,
    const struct sockaddr FAR* to,
    int tolen
);
static SendToPtr sRealSendTo = (SendToPtr)GetProcAddress(hLib, "sendto");

static SOCKET sProxySock = 0;
static uint16_t sProxyUDPPort = 0;
static BOOL sProxyEnabled = FALSE;

// Old pcaps make it seem like sizeof() sometimes includes alignment
// padding at the end of struct. Maybe not.
const size_t SOCKS_DATAGRAM_HEADER_SIZE = 10;

#pragma pack(push, 1)
struct socks5_datagram_header_t {
    uint16_t reserved;
    uint8_t fragment;
    uint8_t address_type;
    uint32_t address;
    uint16_t port;
};
#pragma pack(pop)


BOOL is_proxied_datagram(SOCKET s, const struct sockaddr* addr) {
    int sock_type;
    int length = sizeof(int);

    // Fail if we can't get socket option
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&sock_type, &length)) {
        return FALSE;
    }

    // UDP only
    if (sock_type != SOCK_DGRAM) {
        return FALSE;
    }

    // Addr has to be provided
    if (addr == nullptr) {
        return FALSE;
    }

    // IPv4 only.
    if (addr->sa_family != AF_INET) {
        return FALSE;
    }

    sockaddr_in* addr_in = (sockaddr_in*)addr;
    // Pass DNS through as-is no matter what.
    if (ntohs(addr_in->sin_port) == 53)
        return FALSE;

    return TRUE;
}

int
WSAAPI
fake_recvfrom(
    _In_ SOCKET s,
    _Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR* buf,
    _In_ int len,
    _In_ int flags,
    _Out_writes_bytes_to_opt_(*fromlen, *fromlen) struct sockaddr FAR* from,
    _Inout_opt_ int FAR* fromlen
) {
    // Pass errors through as-is
    int data_len = sRealRecvFrom(s, buf, len, flags, from, fromlen);
    if (data_len < 0) {
        return data_len;
    }

    // This isn't something that could even potentially be proxied.
    if (!is_proxied_datagram(s, from)) {
        return data_len;
    }

    sockaddr_in* from_in = (sockaddr_in*)from;
    // Didn't actually come from the proxy, pass it through
    if (from_in->sin_addr.s_addr != LOCALHOST) {
        return data_len;
    }

    // Not long enough to even have a header
    if (data_len < SOCKS_DATAGRAM_HEADER_SIZE) {
        goto internal_error;
    }

    const socks5_datagram_header_t socks_header = *((socks5_datagram_header_t *)buf);

    // We don't know how to handle either of these cases.
    if (socks_header.reserved || socks_header.fragment) {
        goto internal_error;
    }

    // lie about who we got the packet from using the SOCKS5 header
    from_in->sin_addr.s_addr = socks_header.address;
    from_in->sin_port = socks_header.port;

    // Remove the datagram header from the start of the buffer
    memmove(buf, buf + SOCKS_DATAGRAM_HEADER_SIZE, data_len - SOCKS_DATAGRAM_HEADER_SIZE);
    data_len -= SOCKS_DATAGRAM_HEADER_SIZE;

    return data_len;

internal_error:
    // Zero is returned for errors on Windows for some reason,
    // even though zero-length datagrams are valid.
    return 0;
}


int
WSAAPI
fake_sendto(
    _In_ SOCKET s,
    _In_reads_bytes_(len) const char FAR* buf,
    _In_ int len,
    _In_ int flags,
    _In_reads_bytes_(tolen) const struct sockaddr FAR* to,
    _In_ int tolen
) {
    if (!is_proxied_datagram(s, to)) {
        return sRealSendTo(s, buf, len, flags, to, tolen);
    }

    // Too large, can't send this
    if (len + SOCKS_DATAGRAM_HEADER_SIZE >= SOCK_BUFLEN) {
        return -1;
    }

    // We can't mutate the original because that will mess with resends, make a copy
    // is_proxied_datagram() verifies that this is af_inet.
    struct sockaddr_in proxy_to = *(sockaddr_in*)to;
    char send_buf[SOCK_BUFLEN] = { 0 };

    // Write the SOCKS5 header at the start of the new packet
    socks5_datagram_header_t* socks_header = (socks5_datagram_header_t*)&send_buf;
    socks_header->address = proxy_to.sin_addr.s_addr;
    socks_header->port = proxy_to.sin_port;
    socks_header->reserved = 0;
    socks_header->fragment = 0;
    socks_header->address_type = 1;

    // rewrite the to address to point to the proxy
    proxy_to.sin_port = sProxyUDPPort;
    proxy_to.sin_addr.s_addr = LOCALHOST;

    // Copy the original data over to the new packet
    memcpy(send_buf + SOCKS_DATAGRAM_HEADER_SIZE, buf, len);
    return sRealSendTo(s, send_buf, len + SOCKS_DATAGRAM_HEADER_SIZE, flags, (sockaddr*)&proxy_to, tolen);
}

BOOL blocking_socks5_handshake() {
    WSADATA wsaData;
    char recvbuf[SOCK_BUFLEN] = {0};
    int recvbuflen = SOCK_BUFLEN;
    int timeout = 1000;
    sockaddr_in proxy_addr = { 0 };

    // We have to start up winsock ourselves since the parent process won't have by this point
    WSAStartup(0x0202, &wsaData);
    sProxySock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sProxySock == INVALID_SOCKET) {
        MessageBox(NULL, TEXT("Couldn't create a socket"), TEXT("Proxy error"), 0);
        return FALSE;
    }
    setsockopt(sProxySock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sProxySock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = LOCALHOST;
    proxy_addr.sin_port = htons(9061);
    if (connect(sProxySock, (const sockaddr*)&proxy_addr, sizeof(sockaddr_in))) {
        MessageBox(NULL, TEXT("Couldn't connect to SOCKS proxy, closing!"), TEXT("Proxy error"), 0);
        return FALSE;
    }
    // SOCKS 5 handshake, no auth
    if (send(sProxySock, "\x05\x01\x00", 3, 0) != 3) {
        goto handshake_failed;
    }

    // failed to send
    if (recv(sProxySock, recvbuf, 2, 0) != 2) {
        goto handshake_failed;
    }
    // not SOCKS or unauthed not allowed.
    if (memcmp(recvbuf, "\x05\x00", 2)) {
        goto handshake_failed;
    }

    // ask for a UDP association
    if (send(sProxySock, "\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00", 10, 0) != 10) {
        MessageBox(NULL, TEXT("Failed to ask for UDP association!"), TEXT("Proxy error"), 0);
        goto handshake_failed;
    }

    if (recv(sProxySock, recvbuf, 10, 0) != 10) {
        goto handshake_failed;
    }

    // Did we fail to get an IPv4 association
    if (memcmp(recvbuf, "\x05\x00\x00\x01", 4)) {
        MessageBox(NULL, TEXT("Didn't get a UDP association"), TEXT("Proxy error"), 0);
        goto handshake_failed;
    }

    // Don't care about the host. We assume it's localhost. Only get the port, network-endian.
    sProxyUDPPort = (*((uint16_t*)&recvbuf[8]));
    sProxyEnabled = TRUE;
    return TRUE;

handshake_failed:
    shutdown(sProxySock, SD_SEND);
    closesocket(sProxySock);
    MessageBox(NULL, TEXT("SOCKS Proxy handshake failed!"), TEXT("Proxy error"), 0);
    return FALSE;
}

//-------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    UNREFERENCED_PARAMETER(hinst);
    UNREFERENCED_PARAMETER(reserved);

    if (DetourIsHelperProcess())
        return TRUE;

    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DetourRestoreAfterWith();

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (blocking_socks5_handshake()) {
            DetourAttach(&(PVOID&)sRealRecvFrom, fake_recvfrom);
            DetourAttach(&(PVOID&)sRealSendTo, fake_sendto);
        }
        else {
            ExitProcess(1);
        }
        error = DetourTransactionCommit();
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (sProxyEnabled) {
            shutdown(sProxySock, SD_SEND);
            closesocket(sProxySock);
            DetourDetach(&(PVOID&)sRealRecvFrom, fake_recvfrom);
            DetourDetach(&(PVOID&)sRealSendTo, fake_sendto);
        }
        error = DetourTransactionCommit();
    }
    return TRUE;
}
