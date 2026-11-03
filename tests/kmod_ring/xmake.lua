-- Unit tests of the swdivert ring consumer (no root, no module). Run with `xmake test kmod_ring_test`. Linux only.
if is_plat("linux") and is_host("linux") then
    target("kmod_ring_test")
        set_kind("binary")
        set_default(false)
        add_files("ring_test.cc")
        add_includedirs("../../kmod/include", "..")
        add_tests("default")
    target_end()
end
