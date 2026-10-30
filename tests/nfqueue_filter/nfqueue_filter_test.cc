// Unit tests for the nftables filter compiler (backends/nfqueue/filter_*). The compiler is pure, so no nft binary or privileges are needed.
#include <cstdint>
#include <string>
#include <vector>

#include "filter_ast.h"
#include "filter_compiler.h"
#include "support/test.h"

namespace {
using Rules = std::vector<std::string>;

struct Compiled
{
	bool		ok = false;
	Rules		rules;
	std::string error;
	uint32_t	position = 0;
};

/// Rules are rendered as "<hook>: <match>" so expectations read like the nft output.
Compiled compile(const std::string& filter, bool forward = false, bool include_forward = false)
{
	Compiled					result;
	std::vector<nfq::CompiledRule> rules;
	result.ok = nfq::compile_filter(filter, forward, rules, result.error, result.position, include_forward);
	for (const nfq::CompiledRule& rule : rules)
		result.rules.push_back(std::string(nfq::hook_name(rule.hook)) + ": " + rule.match);
	return result;
}

Rules rules_of(const std::string& filter, bool forward = false, bool include_forward = false)
{
	const Compiled result = compile(filter, forward, include_forward);
	CHECK(result.ok);
	return result.rules;
}

const std::string kIp = "meta nfproto ipv4";

void test_hook_names()
{
	CHECK(std::string(nfq::hook_name(nfq::Hook::input)) == "input");
	CHECK(std::string(nfq::hook_name(nfq::Hook::output)) == "output");
	CHECK(std::string(nfq::hook_name(nfq::Hook::forward)) == "forward");
}

void test_empty_and_constant_filters()
{
	const Rules everything = {"input: " + kIp, "output: " + kIp};
	CHECK(rules_of("") == everything);
	CHECK(rules_of("  \t\r\n") == everything);
	CHECK(rules_of("true") == everything);
	CHECK(rules_of("ip") == everything);
	CHECK(rules_of("not ipv6") == everything);

	CHECK(rules_of("false").empty());
	CHECK(rules_of("ipv6").empty());
	CHECK(rules_of("not ip").empty());
	CHECK(rules_of("not true").empty());
}

void test_protocols_ports_and_directions()
{
	CHECK(rules_of("tcp") == (Rules{"input: " + kIp + " ip protocol tcp", "output: " + kIp + " ip protocol tcp"}));
	CHECK(rules_of("udp.DstPort == 53") == (Rules{"input: " + kIp + " ip protocol udp udp dport 53", "output: " + kIp + " ip protocol udp udp dport 53"}));
	CHECK(rules_of("tcp.SrcPort == 443 and outbound") == (Rules{"output: " + kIp + " ip protocol tcp tcp sport 443"}));
	CHECK(rules_of("inbound") == (Rules{"input: " + kIp}));
	CHECK(rules_of("outbound") == (Rules{"output: " + kIp}));
	CHECK(rules_of("tcp.DstPort != 80") == (Rules{"input: " + kIp + " ip protocol tcp tcp dport != 80", "output: " + kIp + " ip protocol tcp tcp dport != 80"}));
	CHECK(rules_of("tcp.DstPort == 0x50") == rules_of("tcp.DstPort == 80"));
	CHECK(rules_of("tcp.DstPort == 65535").size() == 2);
}

void test_symbolic_operators_match_the_words()
{
	CHECK(rules_of("tcp && !outbound || udp") == rules_of("tcp and not outbound or udp"));
	CHECK(rules_of("ip.DstAddr != 1.2.3.4") == rules_of("not ip.DstAddr == 1.2.3.4"));
}

void test_precedence_and_parentheses()
{
	// `and` binds tighter than `or`.
	CHECK(rules_of("tcp or udp and outbound") == (Rules{"input: " + kIp + " ip protocol tcp", "output: " + kIp + " ip protocol tcp", "output: " + kIp + " ip protocol udp"}));
	CHECK(rules_of("(tcp or udp) and outbound") == (Rules{"output: " + kIp + " ip protocol tcp", "output: " + kIp + " ip protocol udp"}));
	CHECK(rules_of("((tcp))") == rules_of("tcp"));
	CHECK(rules_of("not not tcp") == rules_of("tcp"));
}

void test_disjunction_expands_to_one_rule_per_clause()
{
	CHECK(rules_of("tcp.DstPort == 8080 or tcp.SrcPort == 8080") ==
		  (Rules{"input: " + kIp + " ip protocol tcp tcp dport 8080", "output: " + kIp + " ip protocol tcp tcp dport 8080",
				 "input: " + kIp + " ip protocol tcp tcp sport 8080", "output: " + kIp + " ip protocol tcp tcp sport 8080"}));
}

void test_negation_uses_de_morgan()
{
	CHECK(rules_of("not (tcp or udp)") ==
		  (Rules{"input: " + kIp + " ip protocol != tcp ip protocol != udp", "output: " + kIp + " ip protocol != tcp ip protocol != udp"}));
	CHECK(rules_of("not tcp and outbound") == (Rules{"output: " + kIp + " ip protocol != tcp"}));
	// not (inbound and tcp) == outbound or not tcp
	CHECK(rules_of("not (inbound and tcp)") ==
		  (Rules{"output: " + kIp, "input: " + kIp + " ip protocol != tcp", "output: " + kIp + " ip protocol != tcp"}));
}

void test_contradictions_produce_no_rules()
{
	CHECK(rules_of("tcp and udp").empty());
	CHECK(rules_of("tcp and not tcp").empty());
	CHECK(rules_of("inbound and outbound").empty());
	CHECK(rules_of("udp.DstPort == 1 and tcp").empty());
	CHECK(rules_of("tcp.Syn and udp").empty());
	CHECK(rules_of("ipv6 and tcp").empty());
}

void test_tcp_flags()
{
	const std::string tcp = kIp + " ip protocol tcp";
	CHECK(rules_of("tcp.Syn and outbound") == (Rules{"output: " + tcp + " tcp flags & syn == syn"}));
	CHECK(rules_of("tcp.Syn == 1 and outbound") == rules_of("tcp.Syn and outbound"));
	CHECK(rules_of("tcp.Syn != 0 and outbound") == rules_of("tcp.Syn and outbound"));
	CHECK(rules_of("tcp.Rst == 0 and outbound") == (Rules{"output: " + tcp + " tcp flags & rst == 0"}));
	CHECK(rules_of("tcp.Rst != 1 and outbound") == rules_of("tcp.Rst == 0 and outbound"));
	// A negated flag test still needs TCP: fields of an absent protocol never match.
	CHECK(rules_of("not tcp.Ack and outbound") == (Rules{"output: " + tcp + " tcp flags & ack == 0"}));
	CHECK(rules_of("tcp.Fin and tcp.Psh and tcp.Urg and outbound") ==
		  (Rules{"output: " + tcp + " tcp flags & fin == fin tcp flags & psh == psh tcp flags & urg == urg"}));
	CHECK(rules_of("tcp.Syn or udp").size() == 4);
}

void test_addresses()
{
	CHECK(rules_of("ip.DstAddr == 1.2.3.4 and outbound") == (Rules{"output: " + kIp + " ip daddr { 1.2.3.4 }"}));
	CHECK(rules_of("ip.SrcAddr != 10.0.0.1 and inbound") == (Rules{"input: " + kIp + " ip saddr != { 10.0.0.1 }"}));
	// ip.Addr matches either side, so it needs one clause per side.
	CHECK(rules_of("ip.Addr == 1.2.3.4 and outbound") == (Rules{"output: " + kIp + " ip saddr { 1.2.3.4 }", "output: " + kIp + " ip daddr { 1.2.3.4 }"}));
	CHECK(rules_of("ip.Addr != 1.2.3.4 and outbound") == (Rules{"output: " + kIp + " ip saddr != { 1.2.3.4 } ip daddr != { 1.2.3.4 }"}));
}

void test_server_lists_become_a_single_set()
{
	CHECK(rules_of("(ip.Addr == 1.1.1.1 or ip.Addr == 2.2.2.2 or ip.Addr == 3.3.3.3) and outbound") ==
		  (Rules{"output: " + kIp + " ip saddr { 1.1.1.1, 2.2.2.2, 3.3.3.3 }", "output: " + kIp + " ip daddr { 1.1.1.1, 2.2.2.2, 3.3.3.3 }"}));
	// Different sides are not merged.
	CHECK(rules_of("(ip.SrcAddr == 1.1.1.1 or ip.DstAddr == 2.2.2.2) and outbound") ==
		  (Rules{"output: " + kIp + " ip saddr { 1.1.1.1 }", "output: " + kIp + " ip daddr { 2.2.2.2 }"}));
}

void test_interfaces()
{
	CHECK(rules_of("ifIdx == 5") == (Rules{"input: " + kIp + " meta iif 5", "output: " + kIp + " meta oif 5"}));
	CHECK(rules_of("ifIdx != 5") == (Rules{"input: " + kIp + " meta iif != 5", "output: " + kIp + " meta oif != 5"}));
	CHECK(rules_of("ifIdx == 4294967295 and inbound") == (Rules{"input: " + kIp + " meta iif 4294967295"}));
	// Forwarded packets traverse two interfaces: either side matches, or neither does.
	CHECK(rules_of("ifIdx == 5", true) == (Rules{"forward: " + kIp + " meta iif 5", "forward: " + kIp + " meta oif 5"}));
	CHECK(rules_of("ifIdx != 5", true) == (Rules{"forward: " + kIp + " meta iif != 5 meta oif != 5"}));
	CHECK(rules_of("ifIdx == 5 and ifIdx == 6", true).size() == 4);
}

void test_forward_path()
{
	CHECK(rules_of("tcp", true) == (Rules{"forward: " + kIp + " ip protocol tcp"}));
	CHECK(rules_of("outbound", true) == (Rules{"forward: " + kIp}));
	// Every forwarded packet counts as outbound, so inbound-only filters match nothing.
	CHECK(rules_of("inbound", true).empty());
	CHECK(rules_of("", true) == (Rules{"forward: " + kIp}));
}

void test_include_forward_adds_the_forward_hook()
{
	CHECK(rules_of("tcp", false, true) ==
		  (Rules{"input: " + kIp + " ip protocol tcp", "output: " + kIp + " ip protocol tcp", "forward: " + kIp + " ip protocol tcp"}));
	CHECK(rules_of("outbound", false, true) == (Rules{"output: " + kIp, "forward: " + kIp}));
	CHECK(rules_of("inbound", false, true) == (Rules{"input: " + kIp}));
	// include_forward is ignored once the filter is already compiled for the forward path.
	CHECK(rules_of("tcp", true, true) == rules_of("tcp", true, false));
}

struct ErrorCase
{
	const char* filter;
	const char* message;
	uint32_t	position;
};

void test_syntax_errors_report_message_and_position()
{
	const ErrorCase cases[] = {
		{"bogus", "unsupported filter term 'bogus'", 0},
		{"tcp and bogus", "unsupported filter term 'bogus'", 8},
		{"tcp and", "expected a filter term, found ''", 7},
		{"tcp or or udp", "expected a filter term, found 'or'", 7},
		{"(tcp", "expected ')'", 4},
		{"tcp )", "unexpected ')'", 4},
		{"tcp udp", "unexpected 'udp'", 4},
		{"tcp $", "unexpected character '$'", 4},
		{"tcp.DstPort = 80", "unexpected character '='", 12},
		{"tcp.DstPort > 80", "unexpected character '>'", 12},
		{"tcp.DstPort", "only == and != are supported for tcp.DstPort", 11},
		{"ip.Addr", "only == and != are supported for ip.Addr", 7},
		{"ip.SrcAddr and tcp", "only == and != are supported for ip.SrcAddr", 11},
		{"tcp.DstPort ==", "invalid port ''", 14},
		{"tcp.DstPort == 70000", "invalid port '70000'", 15},
		{"tcp.DstPort == -1", "unexpected character '-'", 15},
		{"tcp.DstPort == http", "invalid port 'http'", 15},
		{"udp.SrcPort == 80x", "invalid port '80x'", 15},
		{"ip.Addr == 300.1.1.1", "invalid IPv4 address '300.1.1.1'", 11},
		{"ip.Addr == 1.2.3", "invalid IPv4 address '1.2.3'", 11},
		{"ip.DstAddr == host", "invalid IPv4 address 'host'", 14},
		{"tcp.Syn == 2", "invalid flag value '2'", 11},
		{"tcp.Syn ==", "invalid flag value ''", 10},
		{"ifIdx == 4294967296", "invalid interface index '4294967296'", 9},
		{"ifIdx == one", "invalid interface index 'one'", 9},
		{"Tcp", "unsupported filter term 'Tcp'", 0},
		{"tcp.dstport == 80", "unsupported filter term 'tcp.dstport'", 0},
		{"ip6", "unsupported filter term 'ip6'", 0},
	};
	for (const ErrorCase& test_case : cases)
	{
		const Compiled result = compile(test_case.filter);
		if (result.ok || result.error != test_case.message || result.position != test_case.position)
		{
			std::fprintf(stderr, "filter '%s': expected error '%s' at %u, got ok=%d error='%s' at %u\n", test_case.filter, test_case.message, test_case.position,
						 result.ok ? 1 : 0, result.error.c_str(), result.position);
			++test::failure_count();
		}
		CHECK(result.rules.empty());
	}
}

void test_failure_discards_previous_rules()
{
	std::vector<nfq::CompiledRule> rules = {{nfq::Hook::input, "stale"}};
	std::string					   error;
	uint32_t					   position = 0;
	CHECK(!nfq::compile_filter("nonsense", false, rules, error, position));
	CHECK(rules.empty());
	CHECK(nfq::compile_filter("false", false, rules, error, position));
	CHECK(rules.empty());
}

void test_input_text_never_reaches_the_output()
{
	// Anything that could smuggle nft syntax through is rejected by the lexer or parser.
	const char* hostile[] = {
		"tcp; flush ruleset",
		"tcp\nflush ruleset",
		"tcp.DstPort == 80 } ; drop",
		"tcp.DstPort == 80; add rule",
		"ip.Addr == 1.2.3.4 } accept { 5.6.7.8",
		"ifIdx == 1 \"",
		"`tcp`",
		"tcp # comment",
	};
	for (const char* filter : hostile)
	{
		const Compiled result = compile(filter);
		CHECK(!result.ok);
		CHECK(result.rules.empty());
	}

	// Accepted filters only produce rules built from the compiler's own vocabulary.
	const char* accepted[] = {"tcp.DstPort == 0x50 and ip.Addr == 1.2.3.4", "(tcp.Syn or udp) and ifIdx != 3", "not (tcp.Fin and inbound)"};
	for (const char* filter : accepted)
	{
		for (const std::string& rule : rules_of(filter, false, true))
			CHECK(rule.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789 :.{},!=&") == std::string::npos);
	}
}

void test_oversized_expansions_are_rejected()
{
	// Ten two-way alternatives multiply out to 1024 clauses.
	std::string filter;
	for (int index = 0; index < 10; ++index)
	{
		if (!filter.empty())
			filter += " and ";
		filter += "(tcp.DstPort == " + std::to_string(index * 2 + 1) + " or tcp.SrcPort == " + std::to_string(index * 2 + 2) + ")";
	}
	const Compiled result = compile(filter);
	CHECK(!result.ok);
	CHECK(result.error.find("filter is too complex") != std::string::npos);
	CHECK(result.rules.empty());

	// Few enough clauses but too many rules once every hook and interface variant is emitted.
	std::string interfaces = "tcp";
	for (int index = 0; index < 11; ++index)
		interfaces += " and ifIdx == " + std::to_string(index + 1);
	const Compiled variants = compile(interfaces, true);
	CHECK(!variants.ok);
	CHECK(variants.error.find("filter is too complex") != std::string::npos);
}

void test_tokenizer()
{
	using nfq::TokenKind;
	const std::vector<nfq::Token> tokens = nfq::tokenize("a&&b || !c==d!=(e) not and or");
	const TokenKind expected[]			 = {TokenKind::word,   TokenKind::op_and, TokenKind::word,   TokenKind::op_or, TokenKind::op_not, TokenKind::word,
											TokenKind::eq,	   TokenKind::word,	  TokenKind::ne,	TokenKind::lparen, TokenKind::word,  TokenKind::rparen,
											TokenKind::op_not, TokenKind::op_and, TokenKind::op_or, TokenKind::end};
	CHECK(tokens.size() == sizeof(expected) / sizeof(expected[0]));
	for (size_t index = 0; index < tokens.size() && index < sizeof(expected) / sizeof(expected[0]); ++index)
		CHECK(tokens[index].kind == expected[index]);
	CHECK(tokens[0].position == 0 && tokens[2].position == 3 && tokens[3].position == 5 && tokens.back().position == 29);
	CHECK(tokens[0].text == "a" && tokens[3].text == "||");

	// Dots and digits belong to a word so `ip.SrcAddr` and `1.2.3.4` stay single tokens.
	const std::vector<nfq::Token> dotted = nfq::tokenize("ip.SrcAddr == 1.2.3.4");
	CHECK(dotted.size() == 4 && dotted[0].text == "ip.SrcAddr" && dotted[2].text == "1.2.3.4");

	CHECK(nfq::tokenize("").size() == 1 && nfq::tokenize("   ").front().kind == TokenKind::end);

	bool threw = false;
	try
	{
		nfq::tokenize("tcp @");
	}
	catch (const nfq::ParseError& error)
	{
		threw = true;
		CHECK(error.position == 4);
	}
	CHECK(threw);
}
}  // namespace

int main(int argc, char** argv)
{
	static const test::TestCase cases[] = {
		{"hook_names", test_hook_names},
		{"empty_and_constant_filters", test_empty_and_constant_filters},
		{"protocols_ports_and_directions", test_protocols_ports_and_directions},
		{"symbolic_operators_match_the_words", test_symbolic_operators_match_the_words},
		{"precedence_and_parentheses", test_precedence_and_parentheses},
		{"disjunction_expands_to_one_rule_per_clause", test_disjunction_expands_to_one_rule_per_clause},
		{"negation_uses_de_morgan", test_negation_uses_de_morgan},
		{"contradictions_produce_no_rules", test_contradictions_produce_no_rules},
		{"tcp_flags", test_tcp_flags},
		{"addresses", test_addresses},
		{"server_lists_become_a_single_set", test_server_lists_become_a_single_set},
		{"interfaces", test_interfaces},
		{"forward_path", test_forward_path},
		{"include_forward_adds_the_forward_hook", test_include_forward_adds_the_forward_hook},
		{"syntax_errors_report_message_and_position", test_syntax_errors_report_message_and_position},
		{"failure_discards_previous_rules", test_failure_discards_previous_rules},
		{"input_text_never_reaches_the_output", test_input_text_never_reaches_the_output},
		{"oversized_expansions_are_rejected", test_oversized_expansions_are_rejected},
		{"tokenizer", test_tokenizer},
	};
	return test::run_tests("nfqueue_filter", cases, argc, argv);
}
