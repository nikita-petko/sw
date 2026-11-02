-- Unit tests for the nftables filter compiler and the nf_tables netlink batch builder. Both use POSIX headers (and libnftnl/libmnl
-- for the batch builder), so the suites are skipped on Windows. Run with `xmake test nfqueue_filter_test` / `xmake test nft_batch_test`.
if not is_plat("windows") then
    target("nfqueue_filter_test")
        set_kind("binary")
        set_default(false)
        add_files("nfqueue_filter_test.cc")
        add_files("../../backends/nfqueue/filter_lexer.cc", "../../backends/nfqueue/filter_parser.cc", "../../backends/nfqueue/filter_compiler.cc")
        add_includedirs("../../backends/nfqueue", "..")
        add_tests("default")
    target_end()

    target("nft_batch_test")
        set_kind("binary")
        set_default(false)
        add_files("nft_batch_test.cc")
        add_files("../../backends/nfqueue/filter_lexer.cc", "../../backends/nfqueue/filter_parser.cc", "../../backends/nfqueue/filter_compiler.cc", "../../backends/nfqueue/nft_batch.cc")
        add_includedirs("../../backends/nfqueue", "..")
        add_syslinks("nftnl", "mnl")
        add_tests("default")
    target_end()
end
