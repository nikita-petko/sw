-- Linux packet backend on the swdivert kernel module (see pocs/linux_kernel_module_backend.md). Apply to a target with add_rules("backend.kmod").
-- It needs no libraries: the module is driven through ioctl and an mmap'd ring.
-- Select it with `xmake f --linux_backend=kmod`; the default is the NFQUEUE backend.
--
-- The module (kmod/swdivert) is built with the executable against the configured kernel (--kmod_kdir, else the running kernel's headers),
-- stripped, signed when --kmod_sign_key and --kmod_sign_cert are given, and embedded in the executable, which loads it from memory at startup
-- when the system does not have it (backends/kmod/module.cc, section 9.3 and Phase 7 of the PoC document). A module is built for one kernel:
-- to run on others as well, build the module against them (xmake f --kmod_kdir=<tree>; xmake build swdivert) and embed those files too:
--     xmake f --linux_backend=kmod --linux_kmod_extra="swdivert-6.1.ko swdivert-6.8.ko"
-- `xmake f --linux_kmod_embed=n` builds lagsw without a module (it then expects an installed one, see section 9.3); that is also what a
-- machine without the kernel headers needs.
local scriptdir = os.scriptdir()

option("linux_backend")
    set_default("nfqueue")
    set_showmenu(true)
    set_values("nfqueue", "kmod")
    set_description("Packet backend of Linux builds: nfqueue (nftables + NFQUEUE, the default) or kmod (the swdivert kernel module)")
option_end()

option("linux_kmod_embed")
    set_default(true)
    set_showmenu(true)
    set_description("Build the swdivert module with lagsw and embed it in the executable (needs the kernel headers of the target kernel)")
option_end()

option("linux_kmod_extra")
    set_showmenu(true)
    set_description("Space-separated prebuilt swdivert .ko files for other kernels, embedded as they are next to the one built here")
option_end()

rule("backend.kmod")
    add_deps("backend.linux_shared")
    on_load(function (target)
        if not target:is_plat("linux") then
            raise("the kmod backend is only available on Linux")
        end
        target:add("files", path.join(scriptdir, "backend.cc"), path.join(scriptdir, "module.cc"), path.join(scriptdir, "filter_program.cc"))
        target:add("includedirs", scriptdir, path.join(scriptdir, "..", "..", "kmod", "include"))
        target:add("defines", "LAGSW_BACKEND_KMOD")
        target:add("files", path.join(scriptdir, "embedded.cc"))

        local embed = import("embed", {rootdir = path.join(scriptdir, "..", "..", "kmod", "modules")})
        local build_here, extras = embed.plan()
        if build_here or #extras > 0 then
            local gendir = path.join(target:autogendir(), "lagsw_kmod")
            target:data_set("kmod_embed", {build_here = build_here, extras = extras, gendir = gendir})
            target:add("includedirs", gendir)
            target:add("defines", "LAGSW_KMOD_EMBEDDED")
        end
    end)

    before_build(function (target)
        local plan = target:data("kmod_embed")
        if plan then
            import("embed", {rootdir = path.join(scriptdir, "..", "..", "kmod", "modules")}).generate(target, plan.gendir, plan.build_here, plan.extras)
        end
    end)
rule_end()
