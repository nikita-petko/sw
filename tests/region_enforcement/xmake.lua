-- Unit tests for region enforcement, run against the in-memory backend of the engine tests. Run with
-- `xmake test region_enforcement_test`. The suite only exists in builds that have the feature (`--region_enforcement=y`).
if has_config("region_enforcement") then
    target("region_enforcement_test")
        set_kind("binary")
        set_default(false)
        set_rundir(os.projectdir())
        add_files("region_enforcement_test.cc", "../engine/fakes.cc", "../support/platform_stub.cc")
        add_files("../../src/log.cc", "../../src/format.cc", "../../src/packet_headers.cc", "../../src/modules/*.cc", "../../src/packet_engine/*.cc")
        add_includedirs("../../include", "../../src", "..", "../engine")
        add_options("region_enforcement", "pcap_files", "desync_countdown", "forwarded_address_discovery", "netfilter_monitor")
        if not is_plat("windows") then
            add_syslinks("pthread")
        end
        add_tests("default")
    target_end()
end
