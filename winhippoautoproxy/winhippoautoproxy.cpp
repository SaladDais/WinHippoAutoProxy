#include <stdio.h>
#include <tchar.h>
#include <vector>
#include <filesystem>

#include <Windows.h>

#include <detours.h>


#define DLL_NAME _T("socks5udphooker.dll")


static bool endsWith(const std::string& str, const std::string& suffix)
{
    return str.size() >= suffix.size() && 0 == str.compare(str.size() - suffix.size(), suffix.size(), suffix);
}

//-------------------------------------------------------------------------
int main()
{
    STARTUPINFO si = {sizeof(STARTUPINFO)};
    PROCESS_INFORMATION pi;

    TCHAR BinDir[MAX_PATH];
    GetModuleFileName(nullptr, BinDir, _countof(BinDir));
    *_tcsrchr(BinDir, '\\') = '\0';
    SetCurrentDirectory(BinDir);

    // add the agni asset CDN to the no_proxy list, so mitmproxy doesn't process assets we don't care about.
    char old_no_proxy[2000] = { 0 };
    GetEnvironmentVariable("no_proxy", (char*)&old_no_proxy, 2000);
    std::string new_no_proxy(old_no_proxy);
    new_no_proxy = "asset-cdn.glb.agni.lindenlab.com," + new_no_proxy;
    SetEnvironmentVariable(TEXT("no_proxy"), new_no_proxy.c_str());

    // Ask child processes to use the local HTTP proxy
    SetEnvironmentVariable(TEXT("HTTP_PROXY"), TEXT("http://127.0.0.1:9062"));
    SetEnvironmentVariable(TEXT("HTTPS_PROXY"), TEXT("http://127.0.0.1:9062"));

    std::vector<std::filesystem::directory_entry> files;

    // Not a great check, but most viewer should have this here.
    if (!std::filesystem::exists("ca-bundle.crt")) {
        MessageBox(NULL, TEXT("Couldn't find ca-bundle.crt, this exe needs to be put in the viewer directory!"), TEXT("AutoProxy Error"), 0);
        return 1;
    }

    // get all EXE files in the dir
    for (const auto& dirent : std::filesystem::directory_iterator(".")) {
        if (dirent.is_regular_file() && endsWith(dirent.path().filename().string(), ".exe")) {
            files.push_back(dirent);
        }
    }

    // sort by largest
    std::sort(files.begin(), files.end(), [](const auto& a, const auto& b) {
        return a.file_size() > b.file_size(); });

    // should be at least 2, the viewer and us.
    if (files.size() < 2) {
        MessageBox(NULL, TEXT("No EXEs in directory?"), TEXT("AutoProxy Error"), 0);
        return 1;
    }

    // Biggest EXE is probably the viewer. Launch it with detours.
    return DetourCreateProcessWithDll(
        files[0].path().string().c_str(),
        nullptr,
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi,
        DLL_NAME,
        nullptr);
}
