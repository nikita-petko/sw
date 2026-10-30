-- Unit tests for PacketEngine, run against an in-memory capture backend (fakes.cc). Run with `xmake test engine_test`.
target("engine_test")
    set_kind("binary")
    set_default(false)
    set_rundir(os.projectdir())
    add_files("engine_test.cc", "fakes.cc", "../support/platform_stub.cc")
    add_files("../../src/log.cc", "../../src/format.cc", "../../src/packet_headers.cc", "../../src/modules/*.cc", "../../src/packet_engine/*.cc")
    add_includedirs("../../include", "../../src", "..")
    add_options("region_enforcement", "pcap_files", "desync_countdown", "forwarded_address_discovery")
    if not is_plat("windows") then
        add_syslinks("pthread")
    end
    add_tests("default")
