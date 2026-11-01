-- Unit tests for passive latency, run against the in-memory backend of the engine tests. Run with
-- `xmake test passive_latency_test`. The suite only exists in builds that have the feature (`--passive_latency=y`).
if has_config("passive_latency") then
    target("passive_latency_test")
        set_kind("binary")
        set_default(false)
        set_rundir(os.projectdir())
        add_files("passive_latency_test.cc", "../engine/fakes.cc", "../support/platform_stub.cc")
        add_files("../../src/log.cc", "../../src/format.cc", "../../src/packet_headers.cc", "../../src/packet_mode/*.cc", "../../src/passive_latency/*.cc", "../../src/packet_engine/*.cc")
        add_includedirs("../../include", "../../src", "..", "../engine")
        add_options("server_discovery", "region_enforcement", "passive_latency", "pcap_files", "desync_countdown", "forwarded_address_discovery", "netfilter_monitor", "net_monitor")
        if not is_plat("windows") then
            add_syslinks("pthread")
        end
        add_tests("default")
    target_end()
end
