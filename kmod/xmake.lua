-- Out-of-tree Linux kernel modules (the swdivert packet-diversion module, see pocs/linux_kernel_module_backend.md).
-- Modules are built by the kernel's own kbuild, driven from xmake: a target applies add_rules("kmod.module"), lists its sources with
-- add_files("*.c") and gets a <name>.ko in the target directory. xmake stays the single source of truth: the Kbuild file is generated
-- into the build directory and the sources are staged there, so the source tree never receives kbuild output.
--
-- Kernel modules are deliberately not part of the default build (they need the kernel headers of the *target* kernel):
--     xmake build -g kmod                    build every module
--     xmake build swdivert_echo              build one
--     xmake f --kmod_kdir=/path/to/kernel/build   use another kernel (also: KDIR=... in the environment)
-- The default kernel is the running one: /lib/modules/<running kernel>/build.
option("kmod_kdir")
    set_showmenu(true)
    set_description("Kernel build directory for kernel modules (default: $KDIR, else /lib/modules/<running kernel>/build)")
option_end()

if is_plat("linux") then
    add_moduledirs(path.join(os.scriptdir(), "modules"))

    rule("kmod.module")
        on_load(function (target)
            -- xmake must not compile the sources: kbuild owns the compiler, flags and module metadata, and the root-level flags
            -- (-Werror, C++20, LTO, ...) must never reach kernel code. The sources are therefore taken out of the target's file
            -- list. The target stays a (file-less) binary because the project generators skip phony targets, and the commands
            -- of on_buildcmd below are how they learn how the sources are compiled (compile_commands.json for IntelliSense).
            local sources = {}
            for _, file in ipairs(table.wrap(target:get("files"))) do
                table.insert(sources, file)
            end
            target:data_set("kmod.sources", sources)
            target:set("files", nil)
            target:set("kind", "binary")
            target:set("extension", ".ko")
            target:set("default", false)
            target:set("group", target:get("group") or "kmod")
        end)

        -- Linking is part of kbuild
        on_link(function (target) end)

        -- Only a real build needs a usable kernel tree. The commands below are also evaluated by the project generators
        -- (compile_commands.json), where raising would make IntelliSense generation fail on machines without kernel headers.
        before_build(function (target)
            import("kbuild").check_kernel_dir()
        end)

        on_buildcmd(function (target, batchcmds, opt)
            import("kbuild").build_commands(target, batchcmds, opt)
        end)

        on_clean(function (target)
            os.tryrm(path.join(target:autogendir(), "kbuild"))
            os.tryrm(target:targetfile())
            os.tryrm(target:dependfile(target:targetfile()))
        end)
    rule_end()

    includes("echo")
    includes("swdivert")
end
