-- Linux packet backend on the swdivert kernel module (see pocs/linux_kernel_module_backend.md). Apply to a target with add_rules("backend.kmod").
-- It needs no libraries: the module is driven through ioctl and an mmap'd ring. The module itself is built separately
-- (`xmake build swdivert`, kmod/swdivert) and loaded by lagsw at startup when it runs as root (section 9.3 of the PoC document).
-- Select it with `xmake f --linux_backend=kmod`; the default is the NFQUEUE backend.
local scriptdir = os.scriptdir()
local nfqdir = path.join(scriptdir, "..", "nfqueue")

option("linux_backend")
    set_default("nfqueue")
    set_showmenu(true)
    set_values("nfqueue", "kmod")
    set_description("Packet backend of Linux builds: nfqueue (nftables + NFQUEUE, the default) or kmod (the swdivert kernel module)")
option_end()

rule("backend.kmod")
    on_load(function (target)
        if not target:is_plat("linux") then
            raise("the kmod backend is only available on Linux")
        end
        target:add("files", path.join(scriptdir, "backend.cc"), path.join(scriptdir, "module.cc"), path.join(scriptdir, "filter_program.cc"))
        -- Shared with the NFQUEUE backend: the filter lexer, parser and DNF conversion (so both accept exactly the same filters), the
        -- filter builders the engine uses, the checksum helper and the privilege check
        for _, name in ipairs({"filter_lexer", "filter_parser", "filter_compiler", "filters", "checksums", "privileges"}) do
            target:add("files", path.join(nfqdir, name .. ".cc"))
        end
        target:add("includedirs", scriptdir, nfqdir, path.join(scriptdir, "..", "..", "kmod", "include"))
        target:add("defines", "LAGSW_BACKEND_KMOD")
    end)
rule_end()
