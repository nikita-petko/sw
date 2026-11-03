-- Phase 2 benchmark tools of pocs/linux_kernel_module_backend.md. Linux only, not built by default: `xmake build swbench`.
-- Run through bench.py (see its header); the module itself is built with `xmake build swdivert`.
if is_plat("linux") then
    target("swbench")
        set_kind("binary")
        set_default(false)
        add_files("swbench.cc")
        -- The same lexer, parser and DNF conversion as the NFQUEUE backend, and the compiler that turns its output into filter programs
        add_files("../../backends/kmod/filter_program.cc", "../../backends/nfqueue/filter_lexer.cc", "../../backends/nfqueue/filter_parser.cc", "../../backends/nfqueue/filter_compiler.cc")
        add_includedirs("../../kmod/include", "../../backends/kmod", "../../backends/nfqueue", "../../tests/kmod_vm")
        add_syslinks("netfilter_queue", "nfnetlink", "mnl")
    target_end()
end
