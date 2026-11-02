-- Tests for the profile loader/editor (src/config_tui/): recent-files list, outline editing and the two views driven with keys.
-- Run with `xmake test config_tui_test`. The suite only exists in builds that have the feature (`--config_tui=y`).
if has_config("config_tui") then
    target("config_tui_test")
        set_kind("binary")
        set_default(false)
        set_rundir(os.projectdir())
        add_files("config_tui_test.cc", "../support/platform_stub.cc")
        add_files("../../src/log.cc", "../../src/options/util.cc", "../../src/options/profiles.cc", "../../src/options/validate.cc")
        add_files("../../src/config_tui/recent_files.cc", "../../src/config_tui/outline.cc", "../../src/config_tui/app.cc")
        add_includedirs("../../include", "../../src", "..")
        add_options("server_discovery", "region_enforcement", "passive_latency", "pcap_files", "desync_countdown", "forwarded_address_discovery", "netfilter_monitor", "net_monitor", "config_tui")
        add_tests("default")
end
