-- The swdivert packet-diversion module (capture, hold, modify, inject, filter programs; ABI version 1, see kmod/include/swdivert_abi.h and pocs/linux_kernel_module_backend.md).
target("swdivert")
    add_rules("kmod.module")
    -- lagsw embeds the module (backends/kmod/xmake.lua), which has to be finished before lagsw's own build steps start, not only before it links
    set_policy("build.fence", true)
    add_files("main.c", "ring.c", "hook.c", "hold.c", "inject.c", "prog.c")
    add_includedirs("../include")
    add_headerfiles("../include/swdivert_abi.h", "../include/swdivert_vm.h", "swdivert.h")
target_end()
