-- Placeholder packet backend for non-Windows platforms. Apply to a target with add_rules("backend.stub").
local scriptdir = os.scriptdir()

rule("backend.stub")
    on_load(function (target)
        target:add("files", path.join(scriptdir, "*.cc"))
        target:add("defines", "LAGSW_BACKEND_STUB")
    end)
rule_end()
