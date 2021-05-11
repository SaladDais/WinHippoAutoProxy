set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(socks5udphooker SHARED socks5udphooker.cpp)
target_link_libraries(socks5udphooker PRIVATE lib_detours wsock32 ws2_32)
set_target_properties(socks5udphooker PROPERTIES LINK_FLAGS /EXPORT:DetourFinishHelperProcess,@1,NONAME)

add_executable(WinHippoAutoProxy winhippoautoproxy.cpp)
target_link_libraries(WinHippoAutoProxy lib_detours)
