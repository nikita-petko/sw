-- See build_mode.lua for why this is a function.
function apply_toolchain()
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
    elseif not (get_config("cross") or get_config("sdk")) then
        -- HTTPS for the optional server region lookups (see src/platform/posix/http.cc)
        add_requires("libcurl", "zlib")
    end

    set_warnings("allextra", "error")
    set_languages("cxx20")

    -- always generate debug information
    set_symbols("debug")
end
