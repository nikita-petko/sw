-- Helpers of the kmod.module rule (kmod/xmake.lua).
import("core.base.option")
import("core.project.config")

-- The kernel build directory modules are built against: --kmod_kdir, else $KDIR, else the running kernel's.
function kernel_dir()
    local dir = config.get("kmod_kdir")
    if not dir or #dir == 0 then
        dir = os.getenv("KDIR")
    end
    if not dir or #dir == 0 then
        dir = path.join("/lib/modules", (os.iorun("uname -r")):trim(), "build")
    end
    return dir
end

local function is_prepared(kdir)
    return os.isfile(path.join(kdir, "Makefile")) and (os.isfile(path.join(kdir, "include/generated/autoconf.h")) or os.isfile(path.join(kdir, ".config")))
end

function check_kernel_dir()
    local kdir = kernel_dir()
    if not is_prepared(kdir) then
        raise("kernel build directory '%s' is missing or not prepared for modules.\n"
            .. "Install the kernel headers of the running kernel (Arch: linux-headers, Debian/Ubuntu: linux-headers-$(uname -r), Fedora: kernel-devel)\n"
            .. "or point to another kernel with `xmake f --kmod_kdir=<dir>`.", kdir)
    end
end

-- Kernel source-tree architecture name for the configured xmake architecture
local function kernel_arch(kdir)
    local arch = config.get("arch") or os.arch()
    local map = {x86_64 = "x86", x64 = "x86", i386 = "x86", x86 = "x86", arm64 = "arm64", aarch64 = "arm64", ["arm64-v8a"] = "arm64",
        arm = "arm", armv7 = "arm", riscv64 = "riscv", riscv32 = "riscv", loongarch64 = "loongarch"}
    local name = map[arch] or arch
    return os.isdir(path.join(kdir, "arch", name)) and name or nil
end

-- Flags that make a source file parse the way kbuild compiles it. This is NOT the kbuild command line (which the kernel build
-- owns and which carries compiler-specific flags that clangd and cpptools reject); it only has to be enough for diagnostics,
-- navigation and completion.
local function syntax_flags(target, kdir, srcroot, file)
    local arch = kernel_arch(kdir)
    local compiler = "gcc"
    local autoconf = io.readfile(path.join(kdir, ".config")) or ""
    if autoconf:find("CONFIG_CC_IS_CLANG=y", 1, true) then
        compiler = "clang"
    end
    local flags = {"-nostdinc", "-std=gnu11", "-D__KERNEL__", "-DMODULE",
        "-DKBUILD_MODNAME=\"" .. target:name() .. "\"", "-DKBUILD_BASENAME=\"" .. path.basename(file) .. "\""}
    -- Newer kernels rely on tagged anonymous structs and record the needed compiler flag in their configuration
    local ms_extensions = autoconf:match('CONFIG_CC_MS_EXTENSIONS="([^"]*)"')
    if ms_extensions and #ms_extensions > 0 then
        table.insert(flags, ms_extensions)
    end
    local compiler_include = try { function () return (os.iorunv(compiler, {"-print-file-name=include"})):trim() end }
    if compiler_include and os.isdir(compiler_include) then
        table.join2(flags, {"-isystem", compiler_include})
    end
    local dirs = {}
    if arch then
        table.join2(dirs, {"arch/" .. arch .. "/include", "arch/" .. arch .. "/include/generated"})
    end
    table.join2(dirs, {"include", "include/generated"})
    if arch then
        table.join2(dirs, {"arch/" .. arch .. "/include/uapi", "arch/" .. arch .. "/include/generated/uapi"})
    end
    table.join2(dirs, {"include/uapi", "include/generated/uapi"})
    for _, dir in ipairs(dirs) do
        if os.isdir(path.join(kdir, dir)) then
            table.join2(flags, {"-I", path.join(kdir, dir)})
        end
    end
    for _, header in ipairs({"compiler-version.h", "kconfig.h", "compiler_types.h"}) do
        if os.isfile(path.join(kdir, "include/linux", header)) then
            table.join2(flags, {"-include", path.join(kdir, "include/linux", header)})
        end
    end
    table.insert(flags, "-I" .. srcroot)
    for _, dir in ipairs(target:get("includedirs") or {}) do
        table.insert(flags, "-I" .. path.absolute(dir, os.projectdir()))
    end
    for _, define in ipairs(table.wrap(target:values("kmod.defines"))) do
        table.insert(flags, "-D" .. define)
    end
    return compiler, flags
end

-- Adds the commands that build `<name>.ko` with the kernel's kbuild. Also evaluated by the project generators to learn how
-- the sources are compiled, so it has to be cheap and must not raise when the kernel tree is missing.
function build_commands(target, batchcmds, opt)
    local kdir = kernel_dir()
    if not is_prepared(kdir) then
        return
    end

    local name = target:name()
    local srcroot = target:scriptdir()
    local stage = path.absolute(path.join(target:autogendir(), "kbuild"))
    local ko = target:targetfile()

    local sources, objects, found = {}, {}, {}
    for _, pattern in ipairs(target:data("kmod.sources")) do
        for _, file in ipairs(os.files(path.absolute(pattern, os.projectdir()))) do
            table.insert(found, file)
        end
    end
    for _, file in ipairs(found) do
        if not file:endswith(".c") then
            raise("kmod.module only builds C sources, got '%s'", file)
        end
        local relative = path.relative(file, srcroot)
        assert(not relative:startswith(".."), "kmod.module sources must live below the target's xmake.lua directory: " .. file)
        table.insert(sources, file)
        table.insert(objects, (relative:gsub("%.c$", ".o")))
    end
    assert(#sources > 0, "target(" .. name .. "): add_files(\"*.c\") is empty")

    -- The generated Kbuild file: xmake is the source of truth for what the module consists of and how it is built
    local flags = {"-I$(src)"}
    for _, dir in ipairs(target:get("includedirs") or {}) do
        table.insert(flags, "-I" .. path.absolute(dir, os.projectdir()))
    end
    for _, define in ipairs(table.wrap(target:values("kmod.defines"))) do
        table.insert(flags, "-D" .. define)
    end
    if config.get("mode") == "debug" then
        table.insert(flags, "-DDEBUG")
        table.insert(flags, "-g")
    end
    local kbuild = {"# Generated by kmod/modules/kbuild.lua; do not edit.", "obj-m := " .. name .. ".o"}
    -- A single source named after the module is the module object itself; kbuild rejects a composite of the same name
    if not (#objects == 1 and objects[1] == name .. ".o") then
        table.insert(kbuild, name .. "-y := " .. table.concat(objects, " "))
    end
    table.insert(kbuild, "ccflags-y := " .. table.concat(flags, " "))
    table.insert(kbuild, "")
    local kbuild_text = table.concat(kbuild, "\n")
    local kbuild_file = path.join(stage, "Kbuild")
    if not os.isfile(kbuild_file) or io.readfile(kbuild_file) ~= kbuild_text then
        os.mkdir(stage)
        io.writefile(kbuild_file, kbuild_text)
    end

    batchcmds:show_progress(opt.progress, "${color.build.target}building.kmod %s", name)

    -- Checks the sources with the kernel's headers first. Its result is ignored (kbuild below is the judge); it exists so that
    -- the project generators learn how the module sources are compiled, which is what IntelliSense (clangd, cpptools) uses.
    for _, file in ipairs(sources) do
        local compiler, syntax = syntax_flags(target, kdir, srcroot, file)
        batchcmds:execv(compiler, table.join("-fsyntax-only", syntax, file), {try = true, stdout = os.nuldev(), stderr = os.nuldev()})
    end

    -- Only the sources are staged (kbuild needs them below M=); headers are used in place through -I
    for _, file in ipairs(sources) do
        batchcmds:cp(file, path.join(stage, path.relative(file, srcroot)))
    end
    local argv = {"-C", kdir, "M=" .. stage, "-j" .. tostring(option.get("jobs") or os.default_njob()), "modules"}
    if not option.get("verbose") then
        table.join2(argv, {"--no-print-directory", "-s"})
    end
    batchcmds:vrunv("make", argv)
    batchcmds:mkdir(path.directory(ko))
    batchcmds:cp(path.join(stage, name .. ".ko"), ko)

    -- Inputs: every source and header of the target, the generated Kbuild, and the kernel it is built against
    local release = try { function () return io.readfile(path.join(kdir, "include/config/kernel.release")) end } or kdir
    batchcmds:add_depfiles(sources, target:headerfiles() or {})
    batchcmds:add_depvalues(kbuild_text, kdir, release)
    batchcmds:set_depmtime(os.mtime(ko))
    batchcmds:set_depcache(target:dependfile(ko))
end
