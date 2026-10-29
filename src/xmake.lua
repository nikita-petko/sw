target("lagsw")
    set_version("6")
    set_kind("binary")
    add_files("*.cc", "modules/*.cc", "options/*.cc", "packet_engine/*.cc")

    add_includedirs("../include")

    -- Operating-system services (input, timers, HTTPS, ...), one implementation per platform
    if is_plat("windows") then
        add_files("platform/windows/*.cc")
    else
        add_files("platform/posix/*.cc")
        add_packages("libcurl")
        -- The static libcurl from vcpkg does not propagate its zlib dependency to the link line
        add_packages("zlib")
    end

    -- Packet capture backend; WinDivert is Windows-only, other platforms use the stub until a real backend exists
    if is_plat("windows") then
        add_rules("backend.windivert")

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
    elseif is_plat("linux") then
        add_rules("backend.nfqueue")
    else
        add_rules("backend.stub")
    end

    -- `xmake package [-o <dir>] lagsw` creates <dir>/lagsw-<version>-<arch>-<mode>/ and a matching .zip (default dir: dist)
    on_package(function (target)
        import("core.base.option")

        local name = format("%s-v%s-%s-%s", target:name(), target:version(), target:arch(), get_config("mode"))
        local outdir = path.absolute(option.get("outputdir") or "dist")
        local pkgdir = path.join(outdir, name)
        os.tryrm(pkgdir)
        os.mkdir(pkgdir)

        os.cp(target:targetfile(), pkgdir)
        -- Windows-only helper scripts are skipped on Linux and vice versa
        local scripts = is_plat("windows") and {"*.ps1", "*.cmd"} or {"*.sh"}
        for _, pattern in ipairs(scripts) do
            os.cp(path.join(os.projectdir(), "scripts", pattern), pkgdir)
        end
        os.cp(path.join(os.projectdir(), "profiles"), pkgdir)

        if is_plat("windows") then
            local zip = path.join(outdir, name .. ".zip")
            os.tryrm(zip)
            -- bsdtar ships with Windows 10+
            os.vrunv("tar", {"-a", "-c", "-f", zip, "-C", pkgdir, "."})
            cprint("${green}packaged: %s", zip)
        else
            -- tar preserves the executable bits of the binary and bootstrap.sh
            os.runv("chmod", {"+x", path.join(pkgdir, target:basename())})
            local archive = path.join(outdir, name .. ".tar.gz")
            os.tryrm(archive)
            os.vrunv("tar", {"-czf", archive, "-C", pkgdir, "."})
            cprint("${green}packaged: %s", archive)
        end
    end)
    before_clean(function (target)
        import("core.base.option")
        os.tryrm(path.absolute(option.get("outputdir") or "dist"))
    end)
