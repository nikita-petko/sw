-- Unit tests for the net monitor view, run against the in-memory backend of the engine tests. Run with `xmake test net_monitor_test`.
-- The suite only exists in builds that have the feature (`--net_monitor=y`).
if has_config("net_monitor") then
    target("net_monitor_test")
        set_kind("binary")
        set_default(false)
        set_rundir(os.projectdir())
        add_files("net_monitor_test.cc", "../engine/fakes.cc", "../support/platform_stub.cc")
        add_files("../../src/net_monitor/*.cc")
        add_files("../../src/log/*.cc", "../../src/format.cc", "../../src/packet_headers.cc", "../../src/packet_mode/*.cc", "../../src/passive_latency/*.cc", "../../src/packet_engine/*.cc")
        add_includedirs("../../include", "../../src", "..", "../engine")
        add_defines("LAGSW_NET_MONITOR_TESTING")
        add_options("server_discovery", "region_enforcement", "passive_latency", "pcap_files", "desync_countdown", "forwarded_address_discovery", "netfilter_monitor", "net_monitor")
        if not is_plat("windows") then
            add_syslinks("pthread")
        end
        add_tests("default")
    target_end()
end
