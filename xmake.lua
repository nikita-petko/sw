add_rules("mode.debug", "mode.release")

set_policy("build.ccache", false)

if is_mode("release") then
    set_policy("build.optimization.lto", true)

    set_optimize("fastest")
	add_defines("NDEBUG", "_NDEBUG")

    set_strip("all")
end

if is_mode("debug") then
	add_defines("DEBUG", "_DEBUG")
end

set_encodings("utf-8")

if is_plat("windows") then
    add_defines(
        "_CRT_SECURE_NO_WARNINGS",
        "_UNICODE",
        "UNICODE",
        "_CONSOLE",
        "NOMINMAX",             -- stop Windows SDK defining 'min' and 'max'
        "NOGDI",                -- otherwise Windows.h defines 'GetObject'
        "WIN32_LEAN_AND_MEAN",  -- cut down Windows.h
        "_WIN32_WINNT=0x0A00"
    )
    -- Make builds more deterministic and portable
    add_cxxflags("/d1trimfile:$(curdir)\\")     -- eliminates the base path from __FILE__ paths
    add_cxxflags("/experimental:deterministic") -- (more) deterministic compiler output
    add_ldflags("/PDBALTPATH:%_PDB%")           -- deterministic pdb reference in exe

    add_cxxflags("/Zc:preprocessor") -- Enable preprocessor conformance mode
    -- add_ldflags("/MAP")

    add_cxxflags("/we4668")
elseif not (get_config("cross") or get_config("sdk")) then
    -- HTTPS for the optional server region lookups (see src/platform/posix/http.cc)
    add_requires("libcurl", "zlib")
end

set_warnings("allextra", "error")
set_languages("cxx20")

-- always generate debug information
set_symbols("debug")

-- Optional features (the `features` section of the profiles config). Each one is compiled in only when enabled:
-- `xmake f --pcap_files=y --desync_countdown=n`. A disabled feature's code is left out of the binary entirely and
-- its configuration block is ignored with a warning. Targets opt in with add_options(), see src/xmake.lua.
local features = {
    {name = "server_discovery",            default = true,  description = "Discover the authoritative server from observed traffic"},
    {name = "region_enforcement",          default = true,  description = "Delay packets from servers outside the enforced region"},
    {name = "passive_latency",             default = true,  description = "Apply a configurable baseline delay to filtered packets regardless of profile activation"},
    {name = "pcap_files",                  default = false, description = "Write per-activation PCAP capture files (debugging aid)"},
    {name = "desync_countdown",            default = true,  description = "Show the estimated post-deactivation desync countdown"},
    {name = "forwarded_address_discovery", default = true,  description = "Discover client addresses of forwarded (shared) traffic"},
    {name = "netfilter_monitor",           default = true,  description = "Show NFQUEUE/nftables health on an extra status line (Linux nfqueue backend)"},
    {name = "net_monitor",                 default = true,  description = "Full-screen network statistics view (packets/s, latency, retransmits, charts) opened with a key"},
    {name = "config_tui",                  default = true,  description = "Terminal UI to create and edit profile files, shown when --config is missing and reopened with a key"},
}
for _, feature in ipairs(features) do
    option(feature.name)
        set_default(feature.default)
        set_showmenu(true)
        set_description(feature.description)
        add_defines("LAGSW_FEATURE_" .. feature.name:upper())
    option_end()
end

includes("backends/windivert")
includes("backends/stub")
includes("backends/linux_shared")
includes("backends/nfqueue")
includes("backends/kmod")
includes("kmod")
includes("src/")
includes("tests/options")
includes("tests/packet")
includes("tests/modes")
includes("tests/region")
includes("tests/engine")
includes("tests/config_tui")
includes("tests/region_enforcement")
includes("tests/passive_latency")
includes("tests/net_monitor")
includes("tests/nfqueue_filter")
includes("tests/kmod_echo")
includes("tests/kmod_ring")
includes("tests/kmod_vm")
includes("pocs/linux_kernel_module_backend")
if is_plat("windows") then
    includes("pocs/windivert_benchmark")
    includes("pocs/tcp_tls_proxy")
    includes("pocs/tls_segment_removal")
end

-- `xmake format` rewrites every first-party C/C++ source in place according to .clang-format.
-- `xmake format --check` only reports files that need formatting and fails if there are any (for CI).
task("format")
    set_category("plugin")
    set_menu {
        usage = "xmake format [options]",
        description = "Format all sources according to the .clang-format rules.",
        options = {
            {'c', "check", "k", nil, "Do not modify files; fail if any file is not formatted."},
            {nil, "clang-format", "kv", "clang-format", "The clang-format executable to use."}
        }
    }
    on_run(function ()
        import("core.base.option")
        import("lib.detect.find_program")

        local root = os.projectdir()
        local program = find_program(option.get("clang-format"))
        if not program then
            raise("clang-format not found, install it or pass --clang-format=<path>")
        end

        -- Vendored (win_divert) and generated (build, dist, .xmake, .cache) directories are not ours to format
        local roots = {"backends", "include", "pocs", "src", "tests"}
        local patterns = {"*.cc", "*.cpp", "*.c", "*.h", "*.hpp"}
        local files = {}
        for _, dir in ipairs(roots) do
            for _, pattern in ipairs(patterns) do
                for _, file in ipairs(os.files(path.join(root, dir, "**", pattern))) do
                    table.insert(files, file)
                end
            end
        end
        table.sort(files)
        if #files == 0 then
            print("no source files found")
            return
        end

        local check = option.get("check")
        local failed = {}
        for _, file in ipairs(files) do
            local relative = path.relative(file, root)
            if check then
                local ok = try { function ()
                    os.runv(program, {"--style=file", "--dry-run", "--Werror", file}, {curdir = root})
                    return true
                end }
                if not ok then
                    table.insert(failed, relative)
                end
            else
                os.runv(program, {"--style=file", "-i", file}, {curdir = root})
            end
        end

        if check then
            if #failed > 0 then
                cprint("${color.error}%d of %d files need formatting:", #failed, #files)
                for _, file in ipairs(failed) do
                    print("  " .. file)
                end
                raise("run `xmake format` to fix")
            end
            cprint("${color.success}all %d files are formatted", #files)
        else
            cprint("${color.success}formatted %d files", #files)
        end
    end)
task_end()
