-- Code shared by the Linux packet backends (nfqueue and kmod): the filter lexer, parser and DNF conversion (so both backends accept
-- exactly the same filters), the filter builders the engine uses, the checksum helper and the privilege check.
-- Applied by the backend rules (add_deps("backend.linux_shared")); it is not meant to be added to a target directly.
local scriptdir = os.scriptdir()

rule("backend.linux_shared")
    on_load(function (target)
        if not target:is_plat("linux") then
            raise("the Linux backends are only available on Linux")
        end
        for _, name in ipairs({"filter_lexer", "filter_parser", "filter_compiler", "filters", "checksums", "privileges"}) do
            target:add("files", path.join(scriptdir, name .. ".cc"))
        end
        target:add("includedirs", scriptdir)
    end)
rule_end()
