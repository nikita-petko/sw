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

set_warnings("allextra", "error")
set_languages("cxx20")

-- always generate debug information
set_symbols("debug")

includes("src/")
includes("pocs/tcp_tls_proxy")
includes("pocs/tls_segment_removal")
