-- `xmake package-all` builds and packages lagsw for Windows x86_64, Linux x86_64 and Linux arm64 in one go:
--   Windows: <outputdir>/lagsw-v*-windows-<arch>-<mode>.zip      Linux: <outputdir>/lagsw-v*-linux-<arch>-<mode>.tar.gz
-- Every target is configured in its own XMAKE_CONFIGDIR below build/package-all, so the project configuration of `xmake f` is
-- left alone. What each target uses depends on the host (see the README, "Cross-compiling"):
--   Windows target: Visual Studio on a Windows host, MinGW-w64 (xmake's mingw platform) on any other
--   Linux target:   the native toolchain when the host is that Linux, otherwise clang + a sysroot that is created with
--                   scripts/build/make_sysroot.py when missing (build/sysroot/<arch>)
task("package-all")
    set_category("plugin")
    set_menu {
        usage = "xmake package-all [options]",
        description = "Build and package lagsw for windows-x86_64, linux-x86_64 and linux-arm64 (zip for Windows, tar.gz for Linux).",
        options = {
            {'m', "mode", "kv", "release", "Build mode: release or debug."},
            {'o', "outputdir", "kv", "dist", "Directory for the packages."},
            {nil, "targets", "kv", "all", "Comma-separated subset of: windows-x86_64, linux-x86_64, linux-arm64."},
            {nil, "linux-backends", "kv", nil, "Comma-separated Linux backends to package, each separately (nfqueue, kmod); the default is the nfqueue backend only."},
            {nil, "kmod-kdir", "kv", nil, "Kernel build tree to embed the kmod module for (xmake f --kmod_kdir); without it, kmod packages for another architecture than the host carry no module."},
            {nil, "mingw", "kv", nil, "MinGW-w64 directory for the Windows target on a non-Windows host."}
        }
    }
    on_run(function ()
        import("core.base.option")
        import("lib.detect.find_program")

        local root = os.projectdir()
        local mode = option.get("mode") or "release"
        local outputdir = path.absolute(option.get("outputdir") or "dist", root)

        local function normalize(arch)
            arch = (arch or ""):lower()
            if arch == "x64" or arch == "amd64" or arch == "x86_64" then
                return "x86_64"
            elseif arch == "arm64" or arch == "aarch64" then
                return "arm64"
            end
            return arch
        end
        local host, host_arch = os.host(), normalize(os.arch())

        local all = {"windows-x86_64", "linux-x86_64", "linux-arm64"}
        local selected = {}
        local requested = option.get("targets") or "all"
        if requested == "all" then
            selected = all
        else
            for name in requested:gmatch("[^,%s]+") do
                if not table.contains(all, name) then
                    raise("unknown target '%s', expected one of: %s", name, table.concat(all, ", "))
                end
                table.insert(selected, name)
            end
        end

        local linux_backends = {}
        for name in (option.get("linux-backends") or ""):gmatch("[^,%s]+") do
            if name ~= "nfqueue" and name ~= "kmod" then
                raise("unknown Linux backend '%s', expected one of: nfqueue, kmod", name)
            end
            if not table.contains(linux_backends, name) then
                table.insert(linux_backends, name)
            end
        end

        local function sysroot_for(arch)
            local dir = path.join(root, "build", "sysroot", arch)
            if not os.isfile(path.join(dir, ".lagsw-sysroot")) then
                local python
                for _, name in ipairs({"python3", "python", "py"}) do
                    python = find_program(name)
                    if python then
                        break
                    end
                end
                if not python then
                    raise("python is needed to create the %s sysroot (scripts/build/make_sysroot.py)", arch)
                end
                cprint("${bright}creating the %s sysroot in %s", arch, dir)
                os.execv(python, {path.join(root, "scripts", "build", "make_sysroot.py"), "--arch", arch, "--dest", dir}, {curdir = root})
            end
            return dir
        end

        -- The xmake f arguments of one target
        local function configure_args(name)
            if name == "windows-x86_64" then
                if host == "windows" then
                    return {"-p", "windows", "-a", "x64"}
                end
                local args = {"-p", "mingw", "-a", "x86_64"}
                if option.get("mingw") then
                    table.join2(args, {"--mingw=" .. option.get("mingw")})
                end
                return args
            end
            local arch = name:sub(#"linux-" + 1)
            if host == "linux" and host_arch == arch then
                return {"-p", "linux", "-a", arch}
            end
            if not find_program("clang") then
                raise("clang (with lld) must be on PATH to build %s on this host, see the README", name)
            end
            return {"-p", "linux", "-a", arch, "--toolchain=clang", "--sysroot=" .. sysroot_for(arch)}
        end

        local xmake = os.programfile()
        local failed = {}
        -- one job per package: Linux targets repeat for every requested backend
        local jobs = {}
        for _, target in ipairs(selected) do
            if target:startswith("linux-") and #linux_backends > 0 then
                for _, backend in ipairs(linux_backends) do
                    table.insert(jobs, {target = target, backend = backend})
                end
            else
                table.insert(jobs, {target = target})
            end
        end

        for _, job in ipairs(jobs) do
            local name = job.target
            local label = job.backend and (name .. "/" .. job.backend) or name
            cprint("${bright}== %s ==", label)
            local failure
            local ok = try { function ()
                local args = configure_args(name)
                local subdir = job.backend and (name .. "-" .. job.backend) or name
                if job.backend then
                    table.insert(args, "--linux_backend=" .. job.backend)
                    local kdir = option.get("kmod-kdir")
                    if kdir then
                        table.insert(args, "--kmod_kdir=" .. kdir)
                    elseif job.backend == "kmod" and name:sub(#"linux-" + 1) ~= host_arch then
                        -- the host's kernel tree cannot build a module for another architecture
                        cprint("${yellow}%s: no module is embedded (another architecture than the host, no --kmod-kdir); lagsw expects an installed one", label)
                        table.insert(args, "--linux_kmod_embed=n")
                    end
                end
                local configdir = path.join(root, "build", "package-all", subdir, "config")
                local builddir = path.join(root, "build", "package-all", subdir, "out")
                os.mkdir(configdir)
                local opts = {curdir = root, envs = {XMAKE_CONFIGDIR = configdir}}
                os.execv(xmake, table.join("f", "-c", "-v", "-y", "-m", mode, "-o", builddir, args), opts)
                os.execv(xmake, {"build", "-v", "lagsw"}, opts)
                os.execv(xmake, {"package", "-v", "-o", outputdir, "lagsw"}, opts)
                return true
            end, catch { function (errors) failure = errors end } }
            if not ok then
                table.insert(failed, label)
                cprint("${color.error}%s failed: %s", label, tostring(failure or "unknown error"))
            end
        end

        if #failed > 0 then
            raise("package-all failed for: %s", table.concat(failed, ", "))
        end
        cprint("${color.success}packages in %s", outputdir)
        for _, file in ipairs(os.files(path.join(outputdir, "*.zip"))) do
            print("  " .. path.filename(file))
        end
        for _, file in ipairs(os.files(path.join(outputdir, "*.tar.gz"))) do
            print("  " .. path.filename(file))
        end
    end)
task_end()
