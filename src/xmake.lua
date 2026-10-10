target("lagsw")
    set_version("5-beta.1")
    set_kind("binary")
    add_files("*.cc", "modules/*.cc", "packet_engine/*.cc", "*.rc")

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

    -- `xmake package [-o <dir>] lagsw` creates <dir>/lagsw-<version>-<arch>-<mode>/ and a matching .zip (default dir: dist)
    on_package(function (target)
        import("core.base.option")

        local name = format("%s-v%s-%s-%s", target:name(), target:version(), target:arch(), get_config("mode"))
        local outdir = path.absolute(option.get("outputdir") or "dist")
        local pkgdir = path.join(outdir, name)
        os.tryrm(pkgdir)
        os.mkdir(pkgdir)

        os.cp(target:targetfile(), pkgdir)
        os.cp(path.join(os.projectdir(), "scripts", "*"), pkgdir)
        os.cp(path.join(os.projectdir(), "profiles"), pkgdir)

        local zip = path.join(outdir, name .. ".zip")
        os.tryrm(zip)
        -- bsdtar ships with Windows 10+
        os.vrunv("tar", {"-a", "-c", "-f", zip, "-C", pkgdir, "."})
        cprint("${green}packaged: %s", zip)
    end)
    before_clean(function (target)
        import("core.base.option")
        os.tryrm(path.absolute(option.get("outputdir") or "dist"))
    end)
