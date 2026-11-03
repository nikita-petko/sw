-- Cross builds (see README, "Cross-compiling"):
--   Linux -> Windows:  xmake f -p mingw --mingw=<MinGW-w64 dir>     (plat "mingw", os "windows")
--   Windows -> Linux:  xmake f -p linux -a x86_64 --toolchain=clang --sysroot=<dir>   (sysroot from scripts/build/make_sysroot.py)
-- Use is_os("windows") for "the target is Windows" (true for the msvc/clang-cl "windows" platform and for "mingw") and
-- is_plat("windows") only for MSVC-specific settings.
option("sysroot")
    set_showmenu(true)
    set_description("Root of the target's headers and libraries for Linux cross builds (see scripts/build/make_sysroot.py)")
option_end()

-- Linux target triples of the architectures that make_sysroot.py can provide, used by clang (gcc cross compilers carry theirs)
local linux_triples = {x86_64 = "x86_64-linux-gnu", x64 = "x86_64-linux-gnu", arm64 = "aarch64-linux-gnu"}

-- Whether the Linux target is built with libraries that come from a sysroot instead of packages built from source
function linux_uses_sysroot()
    return is_plat("linux") and (get_config("cross") or get_config("sdk") or get_config("sysroot")) and true or false
end

-- See build_mode.lua for why this is a function.
function apply_toolchain()
    set_encodings("utf-8")

    if is_os("windows") then
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
    end
    if is_plat("windows") then
        -- Make builds more deterministic and portable
        add_cxxflags("/d1trimfile:$(curdir)\\")     -- eliminates the base path from __FILE__ paths
        add_cxxflags("/experimental:deterministic") -- (more) deterministic compiler output
        add_ldflags("/PDBALTPATH:%_PDB%")           -- deterministic pdb reference in exe

        add_cxxflags("/Zc:preprocessor") -- Enable preprocessor conformance mode
        -- add_ldflags("/MAP")

        add_cxxflags("/we4668")
    elseif is_plat("mingw") then
        -- Self-contained executable: no libstdc++/libgcc/winpthread DLLs next to it
        add_ldflags("-static", {force = true})
    elseif is_plat("linux") then
        local sysroot = get_config("sysroot")
        if sysroot then
            sysroot = path.absolute(sysroot, os.projectdir())
        end
        if sysroot then
            add_cxflags("--sysroot=" .. sysroot, {force = true})
            add_ldflags("--sysroot=" .. sysroot, {force = true})
        end
        local triple = linux_triples[get_config("arch") or ""]
        if sysroot and triple and (get_config("toolchain") or ""):find("clang", 1, true) then
            add_cxflags("--target=" .. triple, {force = true})
            -- The libstdc++/libgcc of the sysroot, whatever the clang build uses by default (LLVM builds for MinGW default to libc++)
            add_cxxflags("-stdlib=libstdc++", {force = true})
            -- clang rejects std::get_temporary_buffer in the libstdc++ 12 headers of Debian 12 (fixed in libstdc++ 13)
            add_cxxflags("-Wno-deprecated-declarations", {force = true})
            add_ldflags("--target=" .. triple, "-fuse-ld=lld", "-stdlib=libstdc++", "-rtlib=libgcc", "-unwindlib=libgcc", {force = true})
        end
        if not linux_uses_sysroot() then
            -- HTTPS for the optional server region lookups (see src/platform/posix/http.cc)
            add_requires("libcurl", "zlib")
        end
    else
        add_requires("libcurl", "zlib")
    end

    set_warnings("allextra", "error")
    set_languages("cxx20")

    -- always generate debug information
    set_symbols("debug")
end
