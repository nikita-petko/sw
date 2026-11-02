-- Phase 2 benchmark tools of pocs/linux_kernel_module_backend.md. Linux only, not built by default: `xmake build swbench`.
-- Run through bench.py (see its header); the module itself is built with `xmake build swdivert`.
if is_plat("linux") then
    target("swbench")
        set_kind("binary")
        set_default(false)
        add_files("swbench.cc")
        add_includedirs("../../kmod/include")
        add_syslinks("netfilter_queue", "nfnetlink", "mnl")
    target_end()
end
