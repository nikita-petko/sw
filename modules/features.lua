-- Optional features (the `features` section of the profiles config). Each one is compiled in only when enabled:
-- `xmake f --pcap_files=y --desync_countdown=n`. A disabled feature's code is left out of the binary entirely and
-- its configuration block is ignored with a warning. Targets opt in with add_options(), see src/xmake.lua.
local features = {
    {name = "server_discovery",            default = true,  description = "Discover the authoritative server from observed traffic"},
    {name = "region_enforcement",          default = true,  description = "Delay packets from servers outside the enforced region"},
    {name = "passive_latency",             default = true,  description = "Apply a configurable baseline delay to filtered packets regardless of profile activation"},
    {name = "pcap_files",                  default = false, description = "Write per-activation PCAP capture files (debugging aid)"},
    {name = "desync_countdown",            default = true,  description = "Show the estimated post-deactivation desync countdown"},
    {name = "forwarded_address_discovery", default = true,  description = "Discover client addresses of forwarded (shared) traffic"},
    {name = "netfilter_monitor",           default = true,  description = "Show NFQUEUE/nftables health on an extra status line (Linux nfqueue backend)"},
    {name = "net_monitor",                 default = true,  description = "Full-screen network statistics view (packets/s, latency, retransmits, charts) opened with a key"},
    {name = "config_tui",                  default = true,  description = "Terminal UI to create and edit profile files, shown when --config is missing and reopened with a key"},
}
for _, feature in ipairs(features) do
    option(feature.name)
        set_default(feature.default)
        set_showmenu(true)
        set_description(feature.description)
        add_defines("LAGSW_FEATURE_" .. feature.name:upper())
    option_end()
end
