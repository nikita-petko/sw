target("lagsw")
    set_version("8")
    set_kind("binary")
    add_files("*.cc", "log/*.cc", "packet_mode/*.cc", "passive_latency/*.cc", "net_monitor/*.cc", "config_tui/*.cc", "options/*.cc", "packet_engine/*.cc")

    -- The version banner; only this file is rebuilt when the commit changes
    on_load(function (target)
        local hash = "unknown"
        local output = try { function () return os.iorunv("git", {"rev-parse", "--short", "HEAD"}, {curdir = os.scriptdir()}) end }
        if output and #output:trim() > 0 then
            hash = output:trim()
        end
        target:add("files", path.join(os.scriptdir(), "version/version.cc"), {defines = {
            "LAGSW_VERSION=\"" .. target:version() .. "\"",
            "LAGSW_GIT_HASH=\"" .. hash .. "\""
        }})
    end)

    add_includedirs("../include")

    -- Compile-time feature toggles, defined in the root xmake.lua
    add_options("server_discovery", "region_enforcement", "passive_latency", "pcap_files", "desync_countdown", "forwarded_address_discovery", "backend_monitor", "net_monitor", "config_tui")

    -- Operating-system services (input, timers, HTTPS, ...), one implementation per platform
    if is_os("windows") then
        add_files("platform/windows/*.cc")
    else
        add_files("platform/posix/*.cc")
        if linux_uses_sysroot() then
            -- Cross builds link the libraries of the target sysroot; building them from source fails with cross toolchains
            add_syslinks("curl", "z")
        else
            add_packages("libcurl")
            -- The static libcurl from vcpkg does not propagate its zlib dependency to the link line
            add_packages("zlib")
        end
    end

    -- Packet capture backend; WinDivert is Windows-only, other platforms use the stub until a real backend exists
    if is_os("windows") then
        add_rules("backend.windivert")

        -- Add UAC admin policy (MinGW builds embed the manifest through the resource file instead)
        if is_plat("windows") then
            set_policy("windows.manifest.uac", "admin")
        end

        -- For timeBeginPeriod
        add_links("winmm")

        -- Link user32 for GetAsyncKeyState
        add_links("user32")

        -- Link winhttp for optional server region lookups
        add_links("winhttp")

        -- Link ole32 for per-capture PCAP GUID generation
        add_links("ole32")

        -- Link iphlpapi for the per-interface error and drop counters of the net monitor
        add_links("iphlpapi")
    elseif is_plat("linux") then
        add_rules(get_config("linux_backend") == "kmod" and "backend.kmod" or "backend.nfqueue")
        -- The kmod backend embeds the swdivert module in the executable, so the module is built first (backends/kmod/xmake.lua)
        if get_config("linux_backend") == "kmod" and get_config("linux_kmod_embed") ~= false then
            add_deps("swdivert")
        end
    else
        add_rules("backend.stub")
    end

    -- `xmake package [-o <dir>] lagsw` creates <dir>/lagsw-<version>-<arch>-<mode>/ and a matching .zip (default dir: dist)
    on_package(function (target)
        import("core.base.option")

        local name = format("%s-v%s-%s-%s", target:name(), target:version(), target:arch(), get_config("mode"))
        local outdir = path.absolute(option.get("outputdir") or "dist")
        -- scripts/package/<os>: "windows" also for MinGW builds
        local targetos = target:plat() == "mingw" and "windows" or target:plat()
        if target:is_plat("linux") and get_config("linux_backend") == "kmod" then
            name = name .. "-kmod"
        end
        local pkgdir = path.join(outdir, name)
        os.tryrm(pkgdir)
        os.mkdir(pkgdir)

        os.cp(target:targetfile(), pkgdir)
        -- only scripts under scripts/package/<plat> are shipped (build and test scripts never are)
        for _, file in ipairs(os.files(path.join(os.projectdir(), "scripts", "package", targetos, "*"))) do
            os.cp(file, pkgdir)
        end
        os.cp(path.join(os.projectdir(), "profiles"), pkgdir)

        if targetos == "windows" then
            local zip = path.join(outdir, name .. ".zip")
            os.tryrm(zip)
            if os.host() == "windows" then
                -- bsdtar ships with Windows 10+
                os.vrunv("tar", {"-a", "-c", "-f", zip, "-C", pkgdir, "."})
            else
                -- MinGW cross build on a Unix host: needs zip or 7z
                import("utils.archive").archive(zip, {"."}, {curdir = pkgdir, recurse = true})
            end
            cprint("${green}packaged: %s", zip)
        else
            -- tar preserves the executable bits of the binary and bootstrap.sh
            if os.host() == "windows" then
                cprint("${yellow}warning: packaging a Linux target on Windows cannot set executable bits; run `chmod +x lagsw bootstrap.sh` after extracting")
            else
                os.runv("chmod", {"+x", path.join(pkgdir, target:basename())})
            end
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
