-- The swdivert packet-diversion module (Phase 2-4 spike: capture, hold, modify, inject, see pocs/linux_kernel_module_backend.md).
target("swdivert")
    add_rules("kmod.module")
    add_files("main.c", "ring.c", "hook.c", "hold.c", "inject.c")
    add_includedirs("../include")
    add_headerfiles("../include/swdivert_abi.h", "swdivert.h")
target_end()
