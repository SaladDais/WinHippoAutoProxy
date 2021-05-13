# What

This is a wrapper program to proxy a Windows Second Life viewer through [Hippolyzer](https://github.com/SaladDais/Hippolyzer/), even if the viewer has broken SOCKS5 support.

# Why

[Pretty much all Windows viewers have broken SOCKS 5 support.](https://jira.secondlife.com/browse/BUG-134040)

# When

Until Windows viewers get their SOCKS 5 support unbroken by someone, maybe you?

# Where

Download https://github.com/SaladDais/WinHippoAutoProxy/releases and extract it into the directory containing your viewer EXE. Launch WinHippoAutoProxy.exe instead of your viewer exe, WinHippoAutoProxy will launch it for you.

If any proxy is configured in the viewer, then disable it. It will conflict with WinHippoAutoProxy.

# How

It intercepts all relevant non-DNS UDP socket send/recv calls and adds or removes a SOCKS header as necessary. These were used to write it:

* https://github.com/microsoft/Detours
* https://github.com/0xeb/detours-cmake

To build it yourself open the folder in Visual Studio 2019 or

```
mkdir build
cd build
cmake -G "Visual Studio 16 2019" ..
cmake --build .
```

# ?

It sucks. Please don't fix it. Fix the viewer so this isn't necessary.
