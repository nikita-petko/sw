-- Linux packet backend using nftables + NFQUEUE. Apply to a target with add_rules("backend.nfqueue").
-- Needs libnetfilter_queue, libnfnetlink and libmnl (system packages) and the `nft` binary at runtime.
local scriptdir = os.scriptdir()

rule("backend.nfqueue")
    on_load(function (target)
        if not target:is_plat("linux") then
            raise("the nfqueue backend is only available on Linux")
        end
        target:add("files", path.join(scriptdir, "*.cc"))
        target:add("includedirs", scriptdir)
        target:add("syslinks", "netfilter_queue", "nfnetlink", "mnl")
        target:add("defines", "LAGSW_BACKEND_NFQUEUE")
    end)
rule_end()
