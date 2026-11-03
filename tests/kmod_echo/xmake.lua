-- User-space half of the kernel-module integration test. Not run by `xmake test` (it needs root and the loaded module):
-- use scripts/tests/test_kmod_echo.sh. Linux only.
if is_plat("linux") then
    target("kmod_echo_test")
        set_kind("binary")
        set_default(false)
        add_files("echo_test.cc")
        add_includedirs("../../kmod/include")
    target_end()
end
