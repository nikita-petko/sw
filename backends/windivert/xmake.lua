-- WinDivert packet backend (Windows only). Apply to a target with add_rules("backend.windivert").
local scriptdir = os.scriptdir()

rule("backend.windivert")
    on_load(function (target)
        if not target:is_plat("windows", "mingw") then
            raise("the WinDivert backend is only available on Windows")
        end
        target:add("files", path.join(scriptdir, "*.cc"), path.join(scriptdir, "*.rc"))
        target:add("includedirs", path.join(scriptdir, "..", "..", "win_divert", "include"))
        target:add("defines", "LAGSW_BACKEND_WINDIVERT")
        -- Service control manager queries of the backend monitor
        target:add("syslinks", "advapi32")
    end)
rule_end()
