add_rules("mode.debug", "mode.release")

set_policy("build.ccache", false)

if is_mode("release") then
    set_policy("build.optimization.lto", true)

    set_optimize("fastest")
	add_defines("NDEBUG", "_NDEBUG")
end

if is_mode("debug") then
	add_defines("DEBUG", "_DEBUG")
end

set_encodings("utf-8")

if is_plat("windows") then
    add_defines(
        "_CRT_SECURE_NO_WARNINGS",
        "_UNICODE",
        "UNICODE",
        "_CONSOLE",
        "NOMINMAX",             -- stop Windows SDK defining 'min' and 'max'
        "NOGDI",                -- otherwise Windows.h defines 'GetObject'
        "WIN32_LEAN_AND_MEAN",  -- cut down Windows.h
        "_WIN32_WINNT=0x0A00"
    )
    -- Make builds more deterministic and portable
    add_cxxflags("/d1trimfile:$(curdir)\\")     -- eliminates the base path from __FILE__ paths
    add_cxxflags("/experimental:deterministic") -- (more) deterministic compiler output
    add_ldflags("/PDBALTPATH:%_PDB%")           -- deterministic pdb reference in exe

    add_cxxflags("/Zc:preprocessor") -- Enable preprocessor conformance mode
    -- add_ldflags("/MAP")

    add_cxxflags("/we4668")
else
    -- HTTPS for the optional server region lookups (see src/platform/posix/http.cc)
    add_requires("libcurl", "zlib")
end

set_warnings("allextra", "error")
set_languages("cxx20")

-- always generate debug information
set_symbols("debug")

-- Optional features (the `features` section of the profiles config). Each one is compiled in only when enabled:
-- `xmake f --pcap_files=y --desync_countdown=n`. A disabled feature's code is left out of the binary entirely and
-- its configuration block is ignored with a warning. Targets opt in with add_options(), see src/xmake.lua.
local features = {
    {name = "region_enforcement",          default = true,  description = "Delay packets from servers outside the enforced region"},
    {name = "pcap_files",                  default = false, description = "Write per-activation PCAP capture files (debugging aid)"},
    {name = "desync_countdown",            default = true,  description = "Show the estimated post-deactivation desync countdown"},
    {name = "forwarded_address_discovery", default = true,  description = "Discover client addresses of forwarded (shared) traffic"},
}
for _, feature in ipairs(features) do
    option(feature.name)
        set_default(feature.default)
        set_showmenu(true)
        set_description(feature.description)
        add_defines("LAGSW_FEATURE_" .. feature.name:upper())
    option_end()
end

includes("backends/windivert")
includes("backends/stub")
includes("backends/nfqueue")
includes("src/")
includes("tests/options")
includes("tests/packet")
includes("tests/modes")
includes("tests/region")
includes("tests/engine")
includes("tests/nfqueue_filter")
if is_plat("windows") then
    includes("pocs/tcp_tls_proxy")
    includes("pocs/tls_segment_removal")
end
