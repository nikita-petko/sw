-- Integration module for the kernel-module build: /dev/swdivert_echo returns what was last written to it. It exists to prove the
-- xmake -> kbuild -> insmod -> user space chain (see scripts/tests/test_kmod_echo.sh), not to be a part of the packet path.
target("swdivert_echo")
    add_rules("kmod.module")
    add_files("echo.c")
    add_includedirs("../include")
    add_headerfiles("../include/swdivert_echo_abi.h")
    -- Not add_defines(): those also carry the repository-wide DEBUG/NDEBUG defines, which must not reach kernel code
    add_values("kmod.defines", "SWDIVERT_ECHO_VERSION=1")
target_end()
