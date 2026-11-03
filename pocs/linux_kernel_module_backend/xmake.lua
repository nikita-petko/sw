-- Phase 2 benchmark tools of pocs/linux_kernel_module_backend.md. Linux only, not built by default: `xmake build swbench`.
-- Run through bench.py (see its header); the module itself is built with `xmake build swdivert`.
if is_plat("linux") then
    target("swbench")
        set_kind("binary")
        set_default(false)
        add_files("swbench.cc")
        -- The same lexer, parser and DNF conversion as the NFQUEUE backend, and the compiler that turns its output into filter programs
        add_files("../../backends/kmod/filter_program.cc", "../../backends/linux_shared/filter_lexer.cc", "../../backends/linux_shared/filter_parser.cc", "../../backends/linux_shared/filter_compiler.cc")
        -- `swbench backend ...` drives the real lagsw backend (backends/kmod) with traffic, so it links it and what it needs
        add_files("backend_cmd.cc", "../../backends/kmod/backend.cc", "../../backends/kmod/module.cc")
        add_files("../../backends/linux_shared/filters.cc", "../../backends/linux_shared/checksums.cc", "../../backends/linux_shared/privileges.cc")
        add_files("../../src/log/*.cc", "../../tests/support/platform_stub.cc")
        add_includedirs("../../include", "../../src", "../../tests")
        add_includedirs("../../kmod/include", "../../backends/kmod", "../../backends/linux_shared", "../../tests/kmod_vm")
        add_syslinks("pthread")
        add_syslinks("netfilter_queue", "nfnetlink", "mnl")
    target_end()
end
