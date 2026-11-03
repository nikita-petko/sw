// Unit tests of the swdivert filter VM (kmod/include/swdivert_vm.h) and of the compiler that produces its programs
// (backends/kmod/filter_program.cc). No root, no module: this is the same code the kernel runs. The differential test compares compiled
// programs with a reference evaluator that reads the filter's syntax tree directly.
#include <chrono>
#include <cstdio>

#include "support.h"
#include "support/test.h"

using namespace vmtest;

namespace {

swdiv_insn I(uint16_t op, uint16_t src = 0, uint32_t a = 0, uint32_t b = 0, uint16_t fail = 0, uint16_t k = 0)
{
	swdiv_insn insn = {};
	insn.op			= op;
	insn.src		= src;
	insn.a			= a;
	insn.b			= b;
	insn.fail		= fail;
	insn.k			= k;
	return insn;
}
swdiv_insn ACCEPT()
{
	return I(SWDIV_OP_ACCEPT);
}

kmodf::Program program(std::vector<swdiv_insn> insns, std::vector<kmodf::SetData> sets = {})
{
	kmodf::Program p;
	p.insns = std::move(insns);
	p.sets	= std::move(sets);
	return p;
}

bool compiles(const std::string& filter, kmodf::Program& out)
{
	std::string error;
	uint32_t	position = 0;
	return kmodf::compile_program(filter, out, error, position);
}

Bytes udp(uint32_t sport, uint32_t dport, size_t payload = 20)
{
	PacketSpec s;
	s.proto = 17;
	s.sport = sport;
	s.dport = dport;
	s.payload.assign(payload, 'x');
	return build(s);
}
Bytes tcp(uint32_t sport, uint32_t dport, uint8_t flags = 0x10, size_t payload = 20)
{
	PacketSpec s;
	s.proto		= 6;
	s.sport		= sport;
	s.dport		= dport;
	s.tcp_flags = flags;
	s.payload.assign(payload, 'x');
	return build(s);
}

void test_comparisons()
{
	const Bytes p = udp(1000, 9000);
	for (const auto& [op, a, expected] : std::vector<std::tuple<uint16_t, uint32_t, bool>>{{SWDIV_OP_EQ, 9000, true},
																						   {SWDIV_OP_EQ, 9001, false},
																						   {SWDIV_OP_NE, 9001, true},
																						   {SWDIV_OP_NE, 9000, false},
																						   {SWDIV_OP_LT, 9001, true},
																						   {SWDIV_OP_LT, 9000, false},
																						   {SWDIV_OP_LE, 9000, true},
																						   {SWDIV_OP_LE, 8999, false},
																						   {SWDIV_OP_GT, 8999, true},
																						   {SWDIV_OP_GT, 9000, false},
																						   {SWDIV_OP_GE, 9000, true},
																						   {SWDIV_OP_GE, 9001, false}})
		CHECK(run(program({I(op, SWDIV_SRC_UDP_DPORT, a, 0, 2), ACCEPT()}), p) == expected);
	CHECK(run(program({I(SWDIV_OP_RANGE, SWDIV_SRC_UDP_DPORT, 8000, 9000, 2), ACCEPT()}), p));
	CHECK(!run(program({I(SWDIV_OP_RANGE, SWDIV_SRC_UDP_DPORT, 8000, 8999, 2), ACCEPT()}), p));
	CHECK(run(program({I(SWDIV_OP_MASK_EQ, SWDIV_SRC_UDP_DPORT, 0xFF00, 0x2300, 2), ACCEPT()}), p));  // 9000 = 0x2328
	CHECK(!run(program({I(SWDIV_OP_MASK_EQ, SWDIV_SRC_UDP_DPORT, 0xFF00, 0x2400, 2), ACCEPT()}), p));
}

void test_a_program_with_no_instructions_matches_nothing_and_accept_matches_everything()
{
	CHECK(!run(program({}), udp(1, 2)));
	CHECK(run(program({ACCEPT()}), udp(1, 2)));
	CHECK(run(program({ACCEPT()}), Bytes{0x45}));  // even a stump: there is no test to fail
}

void test_clauses_fall_through_to_the_next()
{
	// (udp.DstPort == 53) or (udp.DstPort == 9000 and udp.SrcPort == 1000)
	const kmodf::Program p = program({I(SWDIV_OP_EQ, SWDIV_SRC_UDP_DPORT, 53, 0, 2),
									  ACCEPT(),
									  I(SWDIV_OP_EQ, SWDIV_SRC_UDP_DPORT, 9000, 0, 5),
									  I(SWDIV_OP_EQ, SWDIV_SRC_UDP_SPORT, 1000, 0, 5),
									  ACCEPT()});
	CHECK(run(p, udp(7, 53)));
	CHECK(run(p, udp(1000, 9000)));
	CHECK(!run(p, udp(1001, 9000)));
	CHECK(!run(p, udp(1000, 9001)));
}

void test_fields_of_another_protocol_are_absent_even_for_not_equal()
{
	const kmodf::Program ne = program({I(SWDIV_OP_NE, SWDIV_SRC_TCP_DPORT, 80, 0, 2), ACCEPT()});
	CHECK(run(ne, tcp(1, 81)));
	CHECK(!run(ne, tcp(1, 80)));
	CHECK(!run(ne, udp(1, 81)));  // absent, not "not 80"
	PacketSpec icmp;
	icmp.proto = 1;
	CHECK(!run(ne, build(icmp)));
}

void test_a_later_fragment_has_no_ports_and_a_first_fragment_does()
{
	PacketSpec s;
	s.proto = 17;
	s.dport = 9000;
	s.payload.assign(40, 'x');
	const kmodf::Program p = program({I(SWDIV_OP_EQ, SWDIV_SRC_UDP_DPORT, 9000, 0, 2), ACCEPT()});
	CHECK(run(p, build(s)));
	s.frag = 0x2000;  // more fragments, offset 0: the first fragment
	CHECK(run(p, build(s)));
	s.frag = 0x0010;  // offset 16: what follows the header is payload of something else
	CHECK(!run(p, build(s)));
}

void test_truncated_headers_make_fields_absent_instead_of_reading_past_them()
{
	Bytes				 p	   = udp(1000, 9000, 0);  // 28 bytes
	const kmodf::Program ports = program({I(SWDIV_OP_EQ, SWDIV_SRC_UDP_DPORT, 9000, 0, 2), ACCEPT()});
	CHECK(run(ports, p));
	p.resize(23);  // the ports end at byte 24
	CHECK(!run(ports, p));
	const kmodf::Program flags = program({I(SWDIV_OP_MASK_EQ, SWDIV_SRC_TCP_FLAGS, 0x10, 0x10, 2), ACCEPT()});
	Bytes				 t	   = tcp(1, 2, 0x10, 0);
	CHECK(run(flags, t));
	t.resize(33);  // flags are byte 33 of a 20-byte-header packet
	CHECK(!run(flags, t));
}

void test_a_wrong_total_length_hides_what_is_beyond_it()
{
	// Bytes after the IP total length are padding
	Bytes p = udp(1000, 9000, 0);
	p.resize(60, 0xAA);
	const kmodf::Program raw = program({I(SWDIV_OP_EQ, SWDIV_SRC_RAW_BYTE, 0xAA, 0, 2, 40), ACCEPT()});
	CHECK(!run(raw, p));
	put16(p, 2, 60);
	CHECK(run(raw, p));
}

void test_payload_bytes_and_lengths()
{
	PacketSpec s;
	s.proto		  = 17;
	s.payload	  = {'a', 'b', 'c', 'd'};
	const Bytes u = build(s);
	CHECK(run(program({I(SWDIV_OP_EQ, SWDIV_SRC_UDP_PAYLOAD_BYTE, 'c', 0, 2, 2), ACCEPT()}), u));
	CHECK(!run(program({I(SWDIV_OP_EQ, SWDIV_SRC_UDP_PAYLOAD_BYTE, 'x', 0, 2, 4), ACCEPT()}), u));	// byte 4 does not exist
	CHECK(run(program({I(SWDIV_OP_EQ, SWDIV_SRC_UDP_PAYLOAD_LEN, 4, 0, 2), ACCEPT()}), u));
	s.proto		  = 6;
	s.tcp_doff	  = 6;
	const Bytes t = build(s);
	CHECK(run(program({I(SWDIV_OP_EQ, SWDIV_SRC_TCP_PAYLOAD_BYTE, 'a', 0, 2, 0), ACCEPT()}), t));  // after a 24-byte header
	CHECK(run(program({I(SWDIV_OP_EQ, SWDIV_SRC_TCP_PAYLOAD_LEN, 4, 0, 2), ACCEPT()}), t));
	// The prefix is 256 bytes: a payload byte beyond it is absent however long the packet is
	PacketSpec big;
	big.proto = 17;
	big.payload.assign(400, 'z');
	CHECK(run(program({I(SWDIV_OP_EQ, SWDIV_SRC_UDP_PAYLOAD_BYTE, 'z', 0, 2, 200), ACCEPT()}), build(big)));
	CHECK(!run(program({I(SWDIV_OP_EQ, SWDIV_SRC_UDP_PAYLOAD_BYTE, 'z', 0, 2, 250), ACCEPT()}), build(big)));  // 28 + 250 > 256
	CHECK(run(program({I(SWDIV_OP_EQ, SWDIV_SRC_UDP_PAYLOAD_LEN, 400, 0, 2), ACCEPT()}), build(big)));	// lengths come from the header
}

void test_meta_sources()
{
	Meta meta;
	meta.in_ifindex	 = 7;
	meta.out_ifindex = 9;
	meta.mark		 = 0x40;
	const Bytes p	 = udp(1, 2);
	CHECK(run(program({I(SWDIV_OP_EQ, SWDIV_SRC_IN_IFINDEX, 7, 0, 2), ACCEPT()}), p, meta));
	CHECK(run(program({I(SWDIV_OP_EQ, SWDIV_SRC_OUT_IFINDEX, 9, 0, 2), ACCEPT()}), p, meta));
	CHECK(run(program({I(SWDIV_OP_MASK_EQ, SWDIV_SRC_MARK, 0x40, 0x40, 2), ACCEPT()}), p, meta));
	CHECK(run(program({I(SWDIV_OP_EQ, SWDIV_SRC_OUTBOUND, 1, 0, 2), ACCEPT()}), p, meta));
	CHECK(run(program({I(SWDIV_OP_EQ, SWDIV_SRC_PKT_LEN, static_cast<uint32_t>(p.size()), 0, 2), ACCEPT()}), p, meta));
	// Meta tests do not need a packet at all
	CHECK(run(program({I(SWDIV_OP_EQ, SWDIV_SRC_IN_IFINDEX, 7, 0, 2), ACCEPT()}), Bytes{}, meta));
}

void test_sets()
{
	const kmodf::SetData addrs{SWDIV_SET_IPV4, {0x0A0A0102, 0x0A0A0202, 0x0A0A0303}};
	const kmodf::SetData ports{SWDIV_SET_PORTS, {80, 80, 443, 443, 9000, 9100}};
	const kmodf::Program in_src = program({I(SWDIV_OP_IN_SET, SWDIV_SRC_IP_SRC, 0, 0, 2), ACCEPT()}, {addrs});
	CHECK(kmodf::verify_program(in_src).empty());
	PacketSpec s;
	for (uint32_t addr : {0x0A0A0101u, 0x0A0A0102u, 0x0A0A0202u, 0x0A0A0303u, 0x0A0A0304u, 0u, 0xFFFFFFFFu})
	{
		s.src = addr;
		CHECK(run(in_src, build(s)) == (addr == 0x0A0A0102 || addr == 0x0A0A0202 || addr == 0x0A0A0303));
	}
	const kmodf::Program not_in = program({I(SWDIV_OP_NOT_IN_SET, SWDIV_SRC_IP_DST, 0, 0, 2), ACCEPT()}, {addrs});
	s.dst						= 0x0A0A0102;
	CHECK(!run(not_in, build(s)));
	s.dst = 0x0A0A0105;
	CHECK(run(not_in, build(s)));
	const kmodf::Program port_set = program({I(SWDIV_OP_IN_SET, SWDIV_SRC_UDP_DPORT, 0, 0, 2), ACCEPT()}, {ports});
	CHECK(kmodf::verify_program(port_set).empty());
	for (uint32_t port : {79u, 80u, 81u, 442u, 443u, 444u, 8999u, 9000u, 9050u, 9100u, 9101u, 0u, 65535u})
	{
		const bool expected = port == 80 || port == 443 || (port >= 9000 && port <= 9100);
		CHECK(run(port_set, udp(1, port)) == expected);
	}
	CHECK(!run(port_set, tcp(1, 80)));	// a UDP port set says nothing about TCP
	// A set test of an absent field fails even for NOT_IN_SET
	CHECK(!run(program({I(SWDIV_OP_NOT_IN_SET, SWDIV_SRC_UDP_DPORT, 0, 0, 2), ACCEPT()}, {ports}), tcp(1, 80)));
}

void test_the_set_search_agrees_with_a_linear_scan()
{
	Rng rng(7);
	for (int round = 0; round < 200; ++round)
	{
		kmodf::SetData set;
		set.kind = SWDIV_SET_IPV4;
		for (uint32_t i = 0, n = rng.below(70); i < n; ++i)
			set.elems.push_back(rng.below(300));
		std::sort(set.elems.begin(), set.elems.end());
		set.elems.erase(std::unique(set.elems.begin(), set.elems.end()), set.elems.end());
		const kmodf::Program p = program({I(SWDIV_OP_IN_SET, SWDIV_SRC_IP_SRC, 0, 0, 2), ACCEPT()}, {set});
		CHECK(kmodf::verify_program(p).empty());
		PacketSpec s;
		for (uint32_t v = 0; v < 310; ++v)
		{
			s.src = v;
			CHECK(run(p, build(s)) == std::binary_search(set.elems.begin(), set.elems.end(), v));
		}
	}
}

void test_the_verifier_refuses_what_it_must()
{
	const std::vector<kmodf::SetData> one_set{{SWDIV_SET_IPV4, {1, 2, 3}}};
	CHECK(kmodf::verify_program(program({I(SWDIV_OP_EQ, SWDIV_SRC_IP_PROTO, 6, 0, 2), ACCEPT()})).empty());
	// a jump that does not go forward
	CHECK(!kmodf::verify_program(program({I(SWDIV_OP_EQ, SWDIV_SRC_IP_PROTO, 6, 0, 0), ACCEPT()})).empty());
	CHECK(!kmodf::verify_program(program({ACCEPT(), I(SWDIV_OP_EQ, SWDIV_SRC_IP_PROTO, 6, 0, 1)})).empty());
	// a jump past the end
	CHECK(!kmodf::verify_program(program({I(SWDIV_OP_EQ, SWDIV_SRC_IP_PROTO, 6, 0, 3), ACCEPT()})).empty());
	// unknown operation, unknown source
	CHECK(!kmodf::verify_program(program({I(0, SWDIV_SRC_IP_PROTO, 6, 0, 1)})).empty());
	CHECK(!kmodf::verify_program(program({I(12, SWDIV_SRC_IP_PROTO, 6, 0, 1)})).empty());
	CHECK(!kmodf::verify_program(program({I(SWDIV_OP_EQ, 99, 6, 0, 1)})).empty());
	CHECK(!kmodf::verify_program(program({I(SWDIV_OP_EQ, 0, 6, 0, 1)})).empty());
	// a read offset beyond the prefix; an offset where none is allowed
	CHECK(!kmodf::verify_program(program({I(SWDIV_OP_EQ, SWDIV_SRC_RAW_BYTE, 6, 0, 1, 256)})).empty());
	CHECK(kmodf::verify_program(program({I(SWDIV_OP_EQ, SWDIV_SRC_RAW_BYTE, 6, 0, 1, 255)})).empty());
	CHECK(!kmodf::verify_program(program({I(SWDIV_OP_EQ, SWDIV_SRC_IP_PROTO, 6, 0, 1, 1)})).empty());
	// an empty range, nonzero b where it means nothing, a nonzero ACCEPT
	CHECK(!kmodf::verify_program(program({I(SWDIV_OP_RANGE, SWDIV_SRC_IP_TTL, 9, 8, 1)})).empty());
	CHECK(!kmodf::verify_program(program({I(SWDIV_OP_EQ, SWDIV_SRC_IP_TTL, 9, 1, 1)})).empty());
	CHECK(!kmodf::verify_program(program({I(SWDIV_OP_ACCEPT, SWDIV_SRC_IP_TTL)})).empty());
	// sets: a number that does not exist, a set of the wrong kind for the field, unsorted elements, duplicates, overlapping ranges
	CHECK(kmodf::verify_program(program({I(SWDIV_OP_IN_SET, SWDIV_SRC_IP_SRC, 0, 0, 2), ACCEPT()}, one_set)).empty());
	CHECK(!kmodf::verify_program(program({I(SWDIV_OP_IN_SET, SWDIV_SRC_IP_SRC, 1, 0, 2), ACCEPT()}, one_set)).empty());
	CHECK(!kmodf::verify_program(program({I(SWDIV_OP_IN_SET, SWDIV_SRC_UDP_DPORT, 0, 0, 2), ACCEPT()}, one_set)).empty());
	CHECK(!kmodf::verify_program(program({I(SWDIV_OP_IN_SET, SWDIV_SRC_IP_TTL, 0, 0, 2), ACCEPT()}, one_set)).empty());
	CHECK(!kmodf::verify_program(program({}, {{SWDIV_SET_IPV4, {2, 1}}})).empty());
	CHECK(!kmodf::verify_program(program({}, {{SWDIV_SET_IPV4, {1, 1}}})).empty());
	CHECK(!kmodf::verify_program(program({}, {{SWDIV_SET_PORTS, {10, 20, 20, 30}}})).empty());
	CHECK(!kmodf::verify_program(program({}, {{SWDIV_SET_PORTS, {30, 20}}})).empty());
	CHECK(!kmodf::verify_program(program({}, {{SWDIV_SET_PORTS, {10, 70000}}})).empty());
	CHECK(!kmodf::verify_program(program({}, {{99, {1}}})).empty());
	CHECK(kmodf::verify_program(program({}, {{SWDIV_SET_PORTS, {10, 20, 21, 30}}})).empty());
	// size limits
	std::vector<swdiv_insn> big(SWDIV_MAX_INSNS, ACCEPT());
	CHECK(kmodf::verify_program(program(big)).empty());
	big.push_back(ACCEPT());
	CHECK(!kmodf::verify_program(program(big)).empty());
	std::vector<kmodf::SetData> sets(SWDIV_MAX_SETS + 1, kmodf::SetData{SWDIV_SET_IPV4, {1}});
	CHECK(!kmodf::verify_program(program({}, sets)).empty());
}

void test_the_interpreter_stops_even_if_the_verifier_was_bypassed()
{
	// A backward jump must not loop: the interpreter refuses to follow it
	const kmodf::Program loop = program({I(SWDIV_OP_EQ, SWDIV_SRC_IP_PROTO, 6, 0, 0)});
	CHECK(!run(loop, tcp(1, 2)));
	// A set that does not exist
	CHECK(!run(program({I(SWDIV_OP_IN_SET, SWDIV_SRC_IP_SRC, 5, 0, 2), ACCEPT()}), tcp(1, 2)));
}

void test_the_compiler_output_has_the_expected_shape()
{
	kmodf::Program p;
	CHECK(compiles("true", p));
	CHECK(p.insns.size() == 1 && p.insns[0].op == SWDIV_OP_ACCEPT);
	CHECK(compiles("", p));
	CHECK(p.insns.size() == 1);
	CHECK(compiles("false", p));
	CHECK(p.insns.empty());

	CHECK(compiles("udp.DstPort == 9000", p));
	CHECK(p.insns.size() == 3);	 // protocol, port, accept
	CHECK(p.insns[0].op == SWDIV_OP_EQ && p.insns[0].src == SWDIV_SRC_IP_PROTO && p.insns[0].a == 17);
	CHECK(p.insns[1].op == SWDIV_OP_EQ && p.insns[1].src == SWDIV_SRC_UDP_DPORT && p.insns[1].a == 9000);
	CHECK(p.insns[0].fail == 3 && p.insns[1].fail == 3);
	CHECK(kmodf::verify_program(p).empty());

	// A server list is one sorted set, not one test per address
	CHECK(compiles("ip.DstAddr == 10.0.0.3 or ip.DstAddr == 10.0.0.1 or ip.DstAddr == 10.0.0.2 or ip.DstAddr == 10.0.0.1", p));
	CHECK(p.sets.size() == 1 && p.sets[0].elems == (std::vector<uint32_t>{0x0A000001, 0x0A000002, 0x0A000003}));
	CHECK(p.insns.size() == 2 && p.insns[0].op == SWDIV_OP_IN_SET);

	// "either" splits into two clauses; both use the same set
	CHECK(compiles("ip.Addr == 10.0.0.1 or ip.Addr == 10.0.0.2", p));
	CHECK(p.sets.size() == 1 && p.insns.size() == 4);

	// A single address is a plain comparison; a negated list is NOT_IN_SET
	CHECK(compiles("ip.SrcAddr != 10.0.0.1", p));
	CHECK(p.insns[0].op == SWDIV_OP_NE && p.sets.empty());
	CHECK(compiles("ip.SrcAddr != 10.0.0.1 and ip.SrcAddr != 10.0.0.2", p));
	CHECK(kmodf::verify_program(p).empty());

	// An interface matches either side on the forward path
	CHECK(compiles("ifIdx == 4", p));
	CHECK(p.insns.size() == 4 && p.insns[0].src == SWDIV_SRC_IN_IFINDEX && p.insns[2].src == SWDIV_SRC_OUT_IFINDEX);
	// tcp flags
	CHECK(compiles("tcp.Syn and tcp.Ack == 0", p));
	bool saw_set = false, saw_clear = false;
	for (const swdiv_insn& insn : p.insns)
		if (insn.op == SWDIV_OP_MASK_EQ)
			(insn.b ? saw_set : saw_clear) = true;
	CHECK(saw_set && saw_clear);
	// the nfqueue front end's rules about what is valid are the same: errors name a position
	std::string error;
	uint32_t	position = 99;
	CHECK(!kmodf::compile_program("tcp.DstPort == 99999", p, error, position));
	CHECK(!error.empty());
	CHECK(!kmodf::compile_program("tcp.Nope == 1", p, error, position));
}

// The layers of a program and the tests that tell the hooks apart
void test_programs_for_several_hooks_test_the_hook_they_run_at()
{
	auto compile = [](const std::string& filter, bool forward, bool include_forward, kmodf::Program& out) {
		std::string error;
		uint32_t	position = 0;
		return kmodf::compile_program(filter, out, error, position, forward, include_forward);
	};
	auto at = [](const kmodf::Program& p, const Bytes& packet, uint8_t hook, uint32_t in = 2, uint32_t out = 3) {
		Meta meta;
		meta.hook		 = hook;
		meta.in_ifindex	 = hook == 3 ? 0 : in;
		meta.out_ifindex = hook == 1 ? 0 : out;
		return run(p, packet, meta);
	};
	constexpr uint8_t in = 1, fwd = 2, out = 3;
	kmodf::Program	  p;

	// Local traffic is two hooks, forwarded traffic one, "both" all three
	CHECK(compile("udp.DstPort == 9000", false, false, p));
	CHECK(p.layers == (SWDIV_OPEN_LOCAL_IN | SWDIV_OPEN_LOCAL_OUT));
	CHECK(kmodf::verify_program(p).empty());
	CHECK(at(p, udp(1, 9000), in) && at(p, udp(1, 9000), out) && !at(p, udp(1, 9001), out) && !at(p, udp(1, 9001), in));
	CHECK(!at(p, udp(1, 9000), fwd));  // a forwarded packet is not this program's business
	CHECK(compile("udp.DstPort == 9000", true, false, p));
	CHECK(p.layers == SWDIV_OPEN_FORWARD);
	CHECK(at(p, udp(1, 9000), fwd));
	CHECK(compile("udp.DstPort == 9000", false, true, p));
	CHECK(p.layers == (SWDIV_OPEN_LOCAL_IN | SWDIV_OPEN_LOCAL_OUT | SWDIV_OPEN_FORWARD));
	CHECK(at(p, udp(1, 9000), in) && at(p, udp(1, 9000), fwd) && at(p, udp(1, 9000), out));

	// "outbound" and "inbound" narrow the layers (nothing is registered that could not match) and need no hook test
	CHECK(compile("outbound and udp.DstPort == 9000", false, false, p));
	CHECK(p.layers == SWDIV_OPEN_LOCAL_OUT);
	for (const swdiv_insn& insn : p.insns)
		CHECK(insn.src != SWDIV_SRC_HOOK);
	CHECK(compile("inbound and udp.DstPort == 9000", false, false, p));
	CHECK(p.layers == SWDIV_OPEN_LOCAL_IN);
	CHECK(compile("outbound and udp.DstPort == 9000", false, true, p));
	CHECK(p.layers == (SWDIV_OPEN_LOCAL_OUT | SWDIV_OPEN_FORWARD));
	CHECK(at(p, udp(1, 9000), out) && at(p, udp(1, 9000), fwd) && !at(p, udp(1, 9000), in));

	// An interface test follows the hook: the input interface where a packet arrives, the output interface where it leaves
	CHECK(compile("ifIdx == 7", false, false, p));
	CHECK(at(p, udp(1, 2), in, 7, 0) && at(p, udp(1, 2), out, 0, 7) && !at(p, udp(1, 2), in, 5, 0) && !at(p, udp(1, 2), out, 0, 5));
	CHECK(!at(p, udp(1, 2), in, 0, 7));	 // the output interface of an arriving packet does not count

	// A filter that matches nothing has no layers and no instructions
	CHECK(compile("false", false, true, p));
	CHECK(p.layers == 0 && p.insns.empty());
}

void test_a_filter_too_big_for_the_vm_is_refused_with_a_message()
{
	// 70 different address lists: more sets than the kernel takes
	std::string filter;
	for (int i = 0; i < 70; ++i)
		filter += std::string(i ? " and " : "") + "(ip.DstAddr == 10.0." + std::to_string(i) + ".1 or ip.DstAddr == 10.0." +
				  std::to_string(i) + ".2)";
	kmodf::Program p;
	std::string	   error;
	uint32_t	   position = 0;
	CHECK(!kmodf::compile_program(filter, p, error, position));
	CHECK(error.find("address lists") != std::string::npos);
}

// The compiled program and the reference evaluator must agree on every packet for every filter.
void test_compiled_programs_agree_with_the_reference_on_random_filters_and_packets()
{
	Rng		 rng(2026);
	int		 compiled = 0, mixed = 0, always = 0, never = 0;
	uint64_t comparisons = 0;
	for (int round = 0; round < 3000; ++round)
	{
		const std::string filter = random_filter(rng, 1 + rng.below(4));
		kmodf::Program	  program;
		std::string		  error;
		uint32_t		  position = 0;
		if (!kmodf::compile_program(filter, program, error, position))
			continue;  // too complex or a combination the compiler refuses: nothing to compare
		++compiled;
		CHECK(kmodf::verify_program(program).empty());
		const linux_shared::Node tree = linux_shared::parse_filter(filter);
		int				hits = 0, misses = 0;
		for (int p = 0; p < 120; ++p)
		{
			Meta meta;
			meta.in_ifindex		 = 1 + rng.below(4);
			meta.out_ifindex	 = 1 + rng.below(4);
			const Bytes packet	 = random_packet(rng);
			const bool	expected = reference(tree, false, facts_of(packet, meta));
			const bool	actual	 = run(program, packet, meta);
			if (expected != actual)
			{
				std::fprintf(stderr,
							 "MISMATCH filter: %s (reference %d, program %d, packet %zu bytes)\n",
							 filter.c_str(),
							 expected,
							 actual,
							 packet.size());
				CHECK(expected == actual);
				return;
			}
			++comparisons;
			(actual ? hits : misses)++;
		}
		if (hits && misses)
			++mixed;
		else if (hits)
			++always;
		else
			++never;
	}
	std::printf("  %d filters compiled, %llu comparisons: %d matched some packets and not others, %d matched all, %d none\n",
				compiled,
				static_cast<unsigned long long>(comparisons),
				mixed,
				always,
				never);
	CHECK(compiled > 2000);
	CHECK(mixed > 500);	 // the generator exercises both outcomes, not only trivial filters
}

// Not a pass/fail test: the cost of one run of a typical program on this machine (information for the design document).
void test_cost_per_packet()
{
	kmodf::Program server_list;
	CHECK(
		compiles("udp and (ip.DstAddr == 10.10.2.2 or ip.DstAddr == 10.10.2.3 or ip.DstAddr == 10.10.2.4 or ip.DstAddr == 10.10.2.5) and "
				 "udp.DstPort != 53",
				 server_list));
	kmodf::Program big_set;
	{
		std::string filter = "(ip.DstAddr == 1.0.0.1";
		for (int i = 2; i < 2000; ++i)
			filter += " or ip.DstAddr == 1.0." + std::to_string(i / 256) + "." + std::to_string(i % 256);
		CHECK(compiles(filter + ")", big_set));
	}
	Rng				   rng(5);
	std::vector<Bytes> packets;
	for (int i = 0; i < 1000; ++i)
		packets.push_back(random_packet(rng));
	for (const auto& [name, program] :
		 {std::pair<const char*, const kmodf::Program*>{"typical server filter", &server_list}, {"2000-address set", &big_set}})
	{
		const std::vector<swdiv_vm_set> sets   = kmodf::vm_sets(*program);
		uint64_t						hits   = 0;
		const auto						begin  = std::chrono::steady_clock::now();
		constexpr int					rounds = 2000;
		for (int round = 0; round < rounds; ++round)
			for (const Bytes& packet : packets)
			{
				const swdiv_vm_ctx ctx = context(packet, Meta{});
				hits += swdiv_vm_run(program->insns.data(),
									 static_cast<uint32_t>(program->insns.size()),
									 sets.data(),
									 static_cast<uint32_t>(sets.size()),
									 &ctx);
			}
		const double ns = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - begin).count() /
						  (static_cast<double>(rounds) * static_cast<double>(packets.size()));
		std::printf("  %s: %.0f ns per packet (%zu instructions, %zu sets; %llu matches)\n",
					name,
					ns,
					program->insns.size(),
					program->sets.size(),
					static_cast<unsigned long long>(hits));
	}
}

}  // namespace

int main(int argc, char** argv)
{
	static const test::TestCase cases[] = {
		{"comparisons", test_comparisons},
		{"a_program_with_no_instructions_matches_nothing_and_accept_matches_everything",
		 test_a_program_with_no_instructions_matches_nothing_and_accept_matches_everything},
		{"clauses_fall_through_to_the_next", test_clauses_fall_through_to_the_next},
		{"fields_of_another_protocol_are_absent_even_for_not_equal", test_fields_of_another_protocol_are_absent_even_for_not_equal},
		{"a_later_fragment_has_no_ports_and_a_first_fragment_does", test_a_later_fragment_has_no_ports_and_a_first_fragment_does},
		{"truncated_headers_make_fields_absent_instead_of_reading_past_them",
		 test_truncated_headers_make_fields_absent_instead_of_reading_past_them},
		{"a_wrong_total_length_hides_what_is_beyond_it", test_a_wrong_total_length_hides_what_is_beyond_it},
		{"payload_bytes_and_lengths", test_payload_bytes_and_lengths},
		{"meta_sources", test_meta_sources},
		{"sets", test_sets},
		{"the_set_search_agrees_with_a_linear_scan", test_the_set_search_agrees_with_a_linear_scan},
		{"the_verifier_refuses_what_it_must", test_the_verifier_refuses_what_it_must},
		{"the_interpreter_stops_even_if_the_verifier_was_bypassed", test_the_interpreter_stops_even_if_the_verifier_was_bypassed},
		{"the_compiler_output_has_the_expected_shape", test_the_compiler_output_has_the_expected_shape},
		{"programs_for_several_hooks_test_the_hook_they_run_at", test_programs_for_several_hooks_test_the_hook_they_run_at},
		{"a_filter_too_big_for_the_vm_is_refused_with_a_message", test_a_filter_too_big_for_the_vm_is_refused_with_a_message},
		{"compiled_programs_agree_with_the_reference_on_random_filters_and_packets",
		 test_compiled_programs_agree_with_the_reference_on_random_filters_and_packets},
		{"cost_per_packet", test_cost_per_packet},
	};
	return test::run_tests("kmod_vm", cases, argc, argv);
}
