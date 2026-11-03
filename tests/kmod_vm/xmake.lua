-- Unit tests and the fuzz harness of the swdivert filter VM (Phase 5 of pocs/linux_kernel_module_backend.md). Linux only, no root and no
-- kernel module: they build the very header the module includes (kmod/include/swdivert_vm.h) and the user-space compiler that
-- produces programs for it. Run with `xmake test kmod_vm_test` and `xmake test kmod_vm_fuzz`; the sanitizer workflow applies
-- AddressSanitizer/UndefinedBehaviorSanitizer or ThreadSanitizer to the fuzz target, and
-- `xmake build kmod_vm_fuzz && build/.../kmod_vm_fuzz 5000000` runs it longer.
if is_plat("linux") then
    local sources = {
        "../../backends/kmod/filter_program.cc",
        "../../backends/nfqueue/filter_lexer.cc",
        "../../backends/nfqueue/filter_parser.cc",
        "../../backends/nfqueue/filter_compiler.cc",
    }

    target("kmod_vm_test")
        set_kind("binary")
        set_default(false)
        add_files("vm_test.cc")
        add_files(sources)
        add_includedirs("../../kmod/include", "../../backends/kmod", "../../backends/nfqueue", "..")
        add_tests("default")
    target_end()

    target("kmod_vm_fuzz")
        set_kind("binary")
        set_default(false)
        add_files("vm_fuzz.cc")
        add_files(sources)
        add_includedirs("../../kmod/include", "../../backends/kmod", "../../backends/nfqueue", "..")
        add_tests("default", {runargs = {"20000"}})
    target_end()
end
