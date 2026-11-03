-- Linux packet backend using nftables + NFQUEUE, plus an optional eBPF egress tier. Apply to a target with add_rules("backend.nfqueue").
-- Needs libnetfilter_queue, libnfnetlink, libmnl and libnftnl (system packages). The `nft` binary is not needed at runtime.
-- The eBPF tier additionally needs libbpf and, at build time only, clang with the bpf target (the object is embedded in the binary).
local scriptdir = os.scriptdir()

-- `xmake f --linux_bpf=n` builds the NFQUEUE backend only. (The value "auto" cannot be used for an option: xmake reserves it.)
option("linux_bpf")
    set_default(true)
    set_showmenu(true)
    set_description("Build the eBPF egress tier (needs clang with the bpf target and libbpf headers; it is skipped with a warning when they are missing)")
option_end()

rule("backend.nfqueue")
    add_deps("backend.linux_shared")
    on_load(function (target)
        if not target:is_plat("linux") then
            raise("the nfqueue backend is only available on Linux")
        end
        target:add("files", path.join(scriptdir, "*.cc"))
        target:add("includedirs", scriptdir)
        target:add("syslinks", "netfilter_queue", "nfnetlink", "mnl", "nftnl")
        target:add("defines", "LAGSW_BACKEND_NFQUEUE")

        -- The eBPF tier needs clang with the bpf target (build time only) and libbpf's headers (of the sysroot in cross builds).
        local sysroot = get_config("sysroot")
        if sysroot then
            sysroot = path.absolute(sysroot, os.projectdir())
        end
        local header_dirs = sysroot and {path.join(sysroot, "usr", "include")} or {"/usr/include", "/usr/local/include"}
        target:data_set("lagsw_bpf_include_dirs", header_dirs)
        import("lib.detect.find_tool")
        local program, reason
        if get_config("linux_bpf") ~= false then
            local clang = find_tool("clang")
            if not clang then
                reason = "clang was not found"
            else
                local targets = try { function () return os.iorunv(clang.program, {"--print-targets"}) end }
                local has_libbpf = false
                for _, dir in ipairs(header_dirs) do
                    has_libbpf = has_libbpf or os.isfile(path.join(dir, "bpf", "libbpf.h"))
                end
                if not targets or not targets:find("bpf", 1, true) then
                    reason = "clang has no bpf target"
                elseif not has_libbpf then
                    reason = "libbpf headers were not found"
                else
                    program = clang.program
                end
            end
            if not program then
                cprint("${yellow}warning: building without the eBPF tier: %s", reason)
            end
        end
        if program then
            local gendir = path.join(target:autogendir(), "lagsw_bpf")
            target:data_set("lagsw_bpf_clang", program)
            target:data_set("lagsw_bpf_gendir", gendir)
            target:add("files", path.join(scriptdir, "shaper", "shaper_bpf.cc"), path.join(scriptdir, "shaper", "qdisc.cc"))
            target:add("includedirs", gendir)
            target:add("syslinks", "bpf")
            target:add("defines", "LAGSW_BPF")
        else
            target:add("files", path.join(scriptdir, "shaper", "shaper_none.cc"))
        end
    end)

    -- Compiles the egress program and embeds the object as a byte array, so the binary needs neither clang nor kernel headers at runtime.
    before_build(function (target)
        local program = target:data("lagsw_bpf_clang")
        if not program then
            return
        end
        local gendir = target:data("lagsw_bpf_gendir")
        local source = path.join(scriptdir, "shaper", "lagsw.bpf.c")
        local shared = path.join(scriptdir, "shaper", "bpf_shared.h")
        local object = path.join(gendir, "lagsw.bpf.o")
        local header = path.join(gendir, "lagsw_bpf_obj.h")
        if os.isfile(header) and os.mtime(header) >= os.mtime(source) and os.mtime(header) >= os.mtime(shared) then
            return
        end
        os.mkdir(gendir)
        local args = {"-target", "bpf", "-mcpu=v3", "-O2", "-g", "-I", path.join(scriptdir, "shaper")}
        -- Debian-style multiarch layouts keep <asm/*.h> outside /usr/include. A sysroot may carry the headers of every
        -- architecture, so it only contributes the one of the target.
        local triplets = {"x86_64-linux-gnu", "aarch64-linux-gnu", "arm-linux-gnueabihf"}
        if get_config("sysroot") then
            local by_arch = {x86_64 = "x86_64-linux-gnu", x64 = "x86_64-linux-gnu", arm64 = "aarch64-linux-gnu"}
            triplets = {by_arch[get_config("arch") or ""]}
        end
        for _, dir in ipairs(target:data("lagsw_bpf_include_dirs")) do
            for _, triplet in ipairs(triplets) do
                if os.isdir(path.join(dir, triplet)) then
                    table.insert(args, "-I")
                    table.insert(args, path.join(dir, triplet))
                end
            end
            if get_config("sysroot") then
                table.insert(args, "-I")
                table.insert(args, dir)
            end
        end
        table.join2(args, {"-c", source, "-o", object})
        os.vrunv(program, args)
        local bytes = io.readfile(object, {encoding = "binary"})
        local lines = {"// Generated by backends/nfqueue/xmake.lua from shaper/lagsw.bpf.c; do not edit.", "static const unsigned char kLagswBpfObject[] = {"}
        for first = 1, #bytes, 16 do
            local row = {}
            for index = first, math.min(first + 15, #bytes) do
                table.insert(row, string.format("0x%02x", bytes:byte(index)))
            end
            table.insert(lines, "    " .. table.concat(row, ", ") .. ",")
        end
        table.insert(lines, "};")
        table.insert(lines, string.format("static const unsigned long kLagswBpfObjectSize = %d;", #bytes))
        io.writefile(header, table.concat(lines, "\n") .. "\n")
    end)
rule_end()
