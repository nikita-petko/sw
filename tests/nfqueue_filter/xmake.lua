-- Unit tests for the nftables filter compiler. The parser needs <arpa/inet.h>, so the suite is skipped on Windows.
-- Run with `xmake test nfqueue_filter_test`.
if not is_plat("windows") then
    target("nfqueue_filter_test")
        set_kind("binary")
        set_default(false)
        add_files("nfqueue_filter_test.cc")
        add_files("../../backends/nfqueue/filter_lexer.cc", "../../backends/nfqueue/filter_parser.cc", "../../backends/nfqueue/filter_compiler.cc")
        add_includedirs("../../backends/nfqueue", "..")
        add_tests("default")
    target_end()
end
