-- Embeds kernel modules in an executable, the way the WinDivert backend carries its driver: the module is built with the executable, turned
-- into a byte array in a generated header, and loaded from memory at run time when the system does not have it (backends/kmod/module.cc).
--
-- A kernel module is built for one kernel (its "vermagic" names the release and the kernel checks it), so the executable carries one
-- module per kernel release it should run on: the one built here against the configured kernel (--kmod_kdir, else the running kernel)
-- and any prebuilt ones listed in `--linux_kmod_extra="a.ko b.ko"`, which are embedded as they are (build them against the other kernels
-- with `xmake f --kmod_kdir=... && xmake build swdivert`, strip and sign them as needed). At run time the one for the running kernel is chosen.
import("core.project.config")
import("lib.detect.find_tool")
import("kbuild")

-- The prebuilt modules named by --linux_kmod_extra
function extra_modules()
    local files = {}
    for word in (config.get("linux_kmod_extra") or ""):gmatch("%S+") do
        table.insert(files, path.absolute(word, os.projectdir()))
    end
    return files
end

-- Decides, when the target is loaded, what gets embedded: returns whether the module is built here, and the prebuilt ones
function plan()
    local build_here = false
    if config.get("linux_kmod_embed") ~= false then
        local kdir = kbuild.kernel_dir()
        if not kbuild.can_build(kdir) then
            raise("the kmod backend embeds the swdivert module, which needs a prepared kernel build tree for this target, and '%s' is not one.\n"
                .. "Install the kernel headers (Arch: linux-headers, Debian/Ubuntu: linux-headers-$(uname -r), Fedora: kernel-devel), point to another\n"
                .. "kernel with `xmake f --kmod_kdir=<dir>`, or build without the embedded module: `xmake f --linux_kmod_embed=n`.", kdir)
        end
        build_here = true
    end
    return build_here, extra_modules()
end

local function c_array(name, bytes)
    local lines = {string.format("static const unsigned char %s[] = {", name)}
    for first = 1, #bytes, 16 do
        local row = {}
        for index = first, math.min(first + 15, #bytes) do
            table.insert(row, string.format("0x%02x", bytes:byte(index)))
        end
        table.insert(lines, "    " .. table.concat(row, ", ") .. ",")
    end
    table.insert(lines, "};")
    return table.concat(lines, "\n")
end

-- Writes <gendir>/lagsw_kmod_images.h from the module `target` built (stripped of debug information, which the kernel does not need and which is
-- most of the file, then signed if a key is configured) and the prebuilt ones. Called before the executable is compiled.
function generate(target, gendir, build_here, extras)
    local images = {}
    local inputs = {}
    local stamp = {tostring(kbuild.kernel_dir()), tostring(config.get("kmod_sign_key")), tostring(config.get("kmod_sign_cert")), tostring(config.get("kmod_sign_hash"))}
    if build_here then
        local module = target:dep("swdivert")
        assert(module, "the swdivert target is not a dependency of " .. target:name())
        -- The raw kbuild output: swdivert.ko itself may already carry a signature, which stripping would drop
        local raw = path.join(module:autogendir(), "kbuild", "swdivert.ko")
        if not os.isfile(raw) then
            raise("the swdivert module was not built (%s is missing)", raw)
        end
        table.insert(inputs, raw)
        local image = path.join(gendir, "swdivert.embedded.ko")
        table.insert(images, {file = image, source = raw})
    end
    for _, file in ipairs(extras) do
        if not os.isfile(file) then
            raise("--linux_kmod_extra: '%s' does not exist", file)
        end
        table.insert(inputs, file)
        table.insert(images, {file = file})
        table.insert(stamp, file)
    end

    local header = path.join(gendir, "lagsw_kmod_images.h")
    local stamp_file = path.join(gendir, "lagsw_kmod_images.stamp")
    local stamp_text = table.concat(stamp, "\n")
    local fresh = os.isfile(header) and os.isfile(stamp_file) and io.readfile(stamp_file) == stamp_text
    if fresh then
        for _, input in ipairs(inputs) do
            fresh = fresh and os.mtime(header) >= os.mtime(input)
        end
    end
    if fresh then
        return
    end

    os.mkdir(gendir)
    local arrays, entries = {}, {}
    for index, image in ipairs(images) do
        if image.source then
            os.cp(image.source, image.file)
            local strip = find_tool("strip")
            if strip then
                -- Same as `make modules_install INSTALL_MOD_STRIP=1`
                os.vrunv(strip.program, {"--strip-debug", image.file})
            else
                cprint("${yellow}warning: strip was not found: the embedded module keeps its debug information (about 3 MB)")
            end
            local sign_tool, sign_args = kbuild.sign_command(kbuild.kernel_dir(), image.file)
            if sign_tool then
                os.vrunv(sign_tool, sign_args)
            end
        end
        local bytes = io.readfile(image.file, {encoding = "binary"})
        local name = string.format("kLagswKmodImage%d", index - 1)
        table.insert(arrays, c_array(name, bytes))
        table.insert(entries, string.format("    {%s, %d},", name, #bytes))
    end
    local text = {"// Generated by kmod/modules/embed.lua (backends/kmod/xmake.lua); do not edit."}
    table.join2(text, arrays)
    table.insert(text, "struct LagswKmodImage")
    table.insert(text, "{")
    table.insert(text, "    const unsigned char* data;")
    table.insert(text, "    unsigned long        size;")
    table.insert(text, "};")
    table.insert(text, "static const LagswKmodImage kLagswKmodImages[] = {")
    table.join2(text, entries)
    table.insert(text, "};")
    io.writefile(header, table.concat(text, "\n") .. "\n")
    io.writefile(stamp_file, stamp_text)
end
