target("lagsw")
    set_kind("binary")
    add_files("*.cc", "modules/*.cc", "*.rc")

    add_includedirs("../include", "../win_divert/include")

    -- Add UAC admin policy
    set_policy("windows.manifest.uac", "admin")

    -- For timeBeginPeriod
    add_links("winmm")

    -- Link user32 for GetAsyncKeyState
    add_links("user32")

    -- Link winhttp for optional server region lookups
    add_links("winhttp")

    -- Link ole32 for per-capture PCAP GUID generation
    add_links("ole32")