-- Linux packet backend on the swdivert kernel module (see pocs/linux_kernel_module_backend.md). Apply to a target with add_rules("backend.kmod").
-- It needs no libraries: the module is driven through ioctl and an mmap'd ring. The module itself is built separately
-- (`xmake build swdivert`, kmod/swdivert) and loaded by lagsw at startup when it runs as root (section 9.3 of the PoC document).
-- Select it with `xmake f --linux_backend=kmod`; the default is the NFQUEUE backend.
local scriptdir = os.scriptdir()

option("linux_backend")
    set_default("nfqueue")
    set_showmenu(true)
    set_values("nfqueue", "kmod")
    set_description("Packet backend of Linux builds: nfqueue (nftables + NFQUEUE, the default) or kmod (the swdivert kernel module)")
option_end()

rule("backend.kmod")
    add_deps("backend.linux_shared")
    on_load(function (target)
        if not target:is_plat("linux") then
            raise("the kmod backend is only available on Linux")
        end
        target:add("files", path.join(scriptdir, "backend.cc"), path.join(scriptdir, "module.cc"), path.join(scriptdir, "filter_program.cc"))
        target:add("includedirs", scriptdir, path.join(scriptdir, "..", "..", "kmod", "include"))
        target:add("defines", "LAGSW_BACKEND_KMOD")
    end)
rule_end()
