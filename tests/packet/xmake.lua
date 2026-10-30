-- Unit tests for packet parsing and formatting. Run with `xmake test packet_test` / `xmake test format_test` / `xmake test disconnect_detector_test`.
local function unit_test(name, sources)
    target(name)
        set_kind("binary")
        set_default(false)
        set_rundir(os.projectdir())
        add_files(name .. ".cc", "../support/platform_stub.cc", "../../src/log.cc")
        add_files(sources)
        add_includedirs("../../include", "../../src", "..")
        add_options("region_enforcement", "pcap_files", "desync_countdown", "forwarded_address_discovery", "netfilter_monitor")
        add_tests("default")
    target_end()
end

unit_test("packet_test", {"../../src/packet_headers.cc", "../../src/packet_engine/util.cc"})
unit_test("format_test", {"../../src/format.cc"})
unit_test("disconnect_detector_test", {})
