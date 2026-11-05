// Unit tests of the swdivert filter VM (kmod/include/swdivert_vm.h) and of the compiler that produces its programs
// (backends/kmod/filter_program.cc). No root, no module: this is the same code the kernel runs. The differential test compares compiled
// programs with a reference evaluator that reads the filter's syntax tree directly.
#include <chrono>
#include <cstddef>
#include <cstdio>

#include "module_image.h"
#include "payload_hash.h"
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
		int						 hits = 0, misses = 0;
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
// The interface of /dev/swdivert is declared stable (ABI version 1, kmod/include/swdivert_abi.h): the sizes and the ioctl numbers are
// asserted in the header itself, and this writes down the rest, so that a change that would break a program built against it fails here.
void test_the_abi_is_the_one_that_was_declared_stable()
{
	CHECK(SWDIVERT_ABI_VERSION == 1);
	CHECK(std::string(SWDIVERT_DEVICE_NAME) == "swdivert");
#define OFFSET(type, field, expected) CHECK(offsetof(type, field) == (expected))
	OFFSET(swdiv_tuple, proto, 0);
	OFFSET(swdiv_tuple, reserved, 1);
	OFFSET(swdiv_tuple, saddr, 4);
	OFFSET(swdiv_tuple, daddr, 8);
	OFFSET(swdiv_tuple, sport, 12);
	OFFSET(swdiv_tuple, dport, 14);
	OFFSET(swdiv_open_args, slots, 0);
	OFFSET(swdiv_open_args, slot_bytes, 4);
	OFFSET(swdiv_open_args, flags, 8);
	OFFSET(swdiv_open_args, priority, 12);
	OFFSET(swdiv_open_args, data_bytes, 16);
	OFFSET(swdiv_open_args, cons_offset, 24);
	OFFSET(swdiv_open_args, hdr_bytes, 32);
	OFFSET(swdiv_open_args, hold_ms, 36);
	OFFSET(swdiv_open_args, max_held, 40);
	OFFSET(swdiv_open_args, reserved3, 44);
	OFFSET(swdiv_verdict, id, 0);
	OFFSET(swdiv_verdict, verdict, 8);
	OFFSET(swdiv_verdict, status, 12);
	OFFSET(swdiv_verdict, data, 16);
	OFFSET(swdiv_verdict, len, 24);
	OFFSET(swdiv_verdict, flags, 28);
	OFFSET(swdiv_verdict_args, items, 0);
	OFFSET(swdiv_verdict_args, count, 8);
	OFFSET(swdiv_verdict_args, reserved, 12);
	OFFSET(swdiv_inject_args, data, 0);
	OFFSET(swdiv_inject_args, len, 8);
	OFFSET(swdiv_inject_args, flags, 12);
	OFFSET(swdiv_inject_args, ifindex, 16);
	OFFSET(swdiv_inject_args, reserved, 20);
	OFFSET(swdiv_insn, op, 0);
	OFFSET(swdiv_insn, fail, 2);
	OFFSET(swdiv_insn, src, 4);
	OFFSET(swdiv_insn, k, 6);
	OFFSET(swdiv_insn, a, 8);
	OFFSET(swdiv_insn, b, 12);
	OFFSET(swdiv_set_desc, kind, 0);
	OFFSET(swdiv_set_desc, n, 4);
	OFFSET(swdiv_set_desc, elems, 8);
	OFFSET(swdiv_program_args, insns, 0);
	OFFSET(swdiv_program_args, n_insns, 8);
	OFFSET(swdiv_program_args, n_sets, 12);
	OFFSET(swdiv_program_args, sets, 16);
	OFFSET(swdiv_program_args, reserved, 24);
	OFFSET(swdiv_slot_hdr, timestamp_ns, 0);
	OFFSET(swdiv_slot_hdr, id, 8);
	OFFSET(swdiv_slot_hdr, len, 16);
	OFFSET(swdiv_slot_hdr, caplen, 20);
	OFFSET(swdiv_slot_hdr, ifindex_in, 24);
	OFFSET(swdiv_slot_hdr, ifindex_out, 28);
	OFFSET(swdiv_slot_hdr, flags, 32);
	OFFSET(swdiv_slot_hdr, hook, 34);
	OFFSET(swdiv_ring_hdr, abi, 0);
	OFFSET(swdiv_ring_hdr, slots, 4);
	OFFSET(swdiv_ring_hdr, slot_bytes, 8);
	OFFSET(swdiv_ring_hdr, prod, 64);
	// The statistics keep their order (counters are only ever added at the end, into the reserved room), and 8 words of it are left
	OFFSET(swdiv_stats, seen, 0);
	OFFSET(swdiv_stats, held, 48);
	OFFSET(swdiv_stats, held_now, 120);
	OFFSET(swdiv_stats, modified, 128);
	OFFSET(swdiv_stats, inject_failed, 160);
	OFFSET(swdiv_stats, reserved, 168);
#undef OFFSET

	// Values that user space bakes in: verdicts, flags, filter operations and sources, limits
	CHECK(SWDIV_V_RESUME == 1 && SWDIV_V_DROP == 2 && SWDIV_V_RESUME_MOD == 3);
	CHECK(SWDIV_CALC_IP == 1 && SWDIV_CALC_L4 == 2);
	CHECK(SWDIV_OPEN_HOLD == 1 && SWDIV_OPEN_LOCAL_IN == 2 && SWDIV_OPEN_LOCAL_OUT == 4 && SWDIV_OPEN_FORWARD == 8);
	CHECK(SWDIV_SLOT_F_TRUNCATED == 1 && SWDIV_SLOT_F_HELD == 2 && SWDIVERT_SLOT_HDR_BYTES == 48);
	CHECK(SWDIV_OP_ACCEPT == 1 && SWDIV_OP_EQ == 2 && SWDIV_OP_NE == 3 && SWDIV_OP_LT == 4 && SWDIV_OP_LE == 5 && SWDIV_OP_GT == 6 &&
		  SWDIV_OP_GE == 7 && SWDIV_OP_MASK_EQ == 8 && SWDIV_OP_RANGE == 9 && SWDIV_OP_IN_SET == 10 && SWDIV_OP_NOT_IN_SET == 11);
	CHECK(SWDIV_SRC_IP_PROTO == 1 && SWDIV_SRC_IP_SRC == 2 && SWDIV_SRC_IP_DST == 3 && SWDIV_SRC_IP_TTL == 4 && SWDIV_SRC_IP_TOTLEN == 5 &&
		  SWDIV_SRC_IP_FRAG == 6 && SWDIV_SRC_RAW_BYTE == 7 && SWDIV_SRC_TCP_SPORT == 10 && SWDIV_SRC_TCP_DPORT == 11 &&
		  SWDIV_SRC_UDP_SPORT == 12 && SWDIV_SRC_UDP_DPORT == 13 && SWDIV_SRC_TCP_FLAGS == 14 && SWDIV_SRC_TCP_PAYLOAD_BYTE == 15 &&
		  SWDIV_SRC_UDP_PAYLOAD_BYTE == 16 && SWDIV_SRC_TCP_PAYLOAD_LEN == 17 && SWDIV_SRC_UDP_PAYLOAD_LEN == 18 &&
		  SWDIV_SRC_IN_IFINDEX == 30 && SWDIV_SRC_OUT_IFINDEX == 31 && SWDIV_SRC_MARK == 32 && SWDIV_SRC_OUTBOUND == 33 &&
		  SWDIV_SRC_LOOPBACK == 34 && SWDIV_SRC_PKT_LEN == 35 && SWDIV_SRC_HOOK == 36);
	CHECK(SWDIV_SET_IPV4 == 1 && SWDIV_SET_PORTS == 2);
	CHECK(SWDIV_MAX_INSNS == 4096 && SWDIV_MAX_SETS == 64 && SWDIV_MAX_SET_ELEMS == 65536 && SWDIV_MAX_TOTAL_ELEMS == (1U << 20) &&
		  SWDIV_VM_PREFIX == 256);
	CHECK(SWDIV_MAX_PACKET == 65535 && SWDIV_MAX_VERDICTS == 4096 && SWDIV_MAX_HOLD_MS == 600000 && SWDIV_MAX_HELD == 65536);
}

// Which embedded module belongs to the running kernel
std::vector<uint8_t> fake_module(const std::string& vermagic, bool elf = true)
{
	std::vector<uint8_t> image(64, 0);
	if (elf)
		std::memcpy(image.data(),
					"\x7f"
					"ELF",
					4);
	const std::string info = std::string("license=GPL") + '\0' + "vermagic=" + vermagic + '\0' + "name=swdivert" + '\0';
	// .modinfo is a run of NUL-terminated strings, the first one preceded by the NUL that ends the section before it
	image.push_back(0);
	image.insert(image.end(), info.begin(), info.end());
	image.resize(image.size() + 40, 0xAA);
	return image;
}

void test_the_embedded_module_for_the_running_kernel_is_chosen_by_its_vermagic()
{
	using kmodb::ModuleImage;
	const std::vector<uint8_t> older = fake_module("6.1.0-test SMP preempt mod_unload "),
							   newer = fake_module("7.2.11-arch1-1 SMP preempt mod_unload ");
	CHECK(kmodb::image_vermagic(newer.data(), newer.size()) == "7.2.11-arch1-1 SMP preempt mod_unload ");
	CHECK(kmodb::image_release(newer.data(), newer.size()) == "7.2.11-arch1-1");
	CHECK(kmodb::image_release(older.data(), older.size()) == "6.1.0-test");

	// Not a module: no ELF header, too short, nothing, a "vermagic=" that is not at the start of a modinfo string
	const std::vector<uint8_t> not_elf = fake_module("7.2.11-arch1-1 SMP ", false);
	CHECK(kmodb::image_release(not_elf.data(), not_elf.size()).empty());
	const uint8_t tiny[] = {0x7f, 'E', 'L', 'F'};
	CHECK(kmodb::image_release(tiny, sizeof(tiny)).empty());
	CHECK(kmodb::image_release(nullptr, 0).empty());
	std::vector<uint8_t> inside = fake_module("7.2.11-arch1-1 SMP ");
	const std::string	 decoy	= "xvermagic=9.9.9 ";
	inside.insert(inside.begin() + 70, decoy.begin(), decoy.end());
	CHECK(kmodb::image_release(inside.data(), inside.size()) != "9.9.9");

	// A module that ends inside its vermagic is read up to its end, not past it
	std::vector<uint8_t> cut = fake_module("7.2.11-arch1-1");
	cut.resize(cut.size() - 40 - 14);
	CHECK(kmodb::image_release(cut.data(), cut.size()).find("7.2.11") == 0);

	const std::vector<ModuleImage> both = {{older.data(), older.size()}, {newer.data(), newer.size()}, {not_elf.data(), not_elf.size()}};
	std::string					   why;
	const ModuleImage*			   chosen = kmodb::select_image(both, "7.2.11-arch1-1", why);
	CHECK(chosen == &both[1]);
	CHECK(kmodb::select_image(both, "6.1.0-test", why) == &both[0]);
	// No image for this kernel: the reason names the kernels there are modules for (and not the one that is not a module)
	CHECK(kmodb::select_image(both, "6.8.0-other", why) == nullptr);
	CHECK(why.find("6.1.0-test") != std::string::npos && why.find("7.2.11-arch1-1") != std::string::npos &&
		  why.find("6.8.0-other") != std::string::npos);
	CHECK(kmodb::select_image({}, "7.2.11-arch1-1", why) == nullptr && why.find("no module is embedded") != std::string::npos);
	// A release that only starts like another one is another kernel
	CHECK(kmodb::select_image(both, "7.2.1", why) == nullptr);
	CHECK(kmodb::select_image(both, "7.2.11-arch1-1-lts", why) == nullptr);
}

// The fingerprint that decides whether a packet is resumed as it is or as new bytes
void test_the_payload_fingerprint_sees_every_edit()
{
	Rng rng(77);
	// Sizes around every loop boundary of the hash: empty, the 8-byte and 32-byte steps, their remainders, a full MTU, a jumbo packet
	const uint32_t sizes[] = {0, 1, 7, 8, 9, 31, 32, 33, 39, 40, 41, 63, 64, 65, 228, 1240, 1500, 9000};
	for (uint32_t size : sizes)
	{
		std::vector<uint8_t> bytes(size);
		for (uint8_t& byte : bytes)
			byte = static_cast<uint8_t>(rng.next());
		const uint64_t original = kmodb::hash_payload(bytes.data(), size);
		CHECK(kmodb::hash_payload(bytes.data(), size) == original);	 // deterministic
		// Every single-bit edit changes it, at every position: this is the engine's case (it edits, it does not forge)
		bool all_seen = true;
		for (uint32_t bit = 0; bit < size * 8; ++bit)
		{
			bytes[bit / 8] ^= static_cast<uint8_t>(1u << (bit % 8));
			all_seen = all_seen && kmodb::hash_payload(bytes.data(), size) != original;
			bytes[bit / 8] ^= static_cast<uint8_t>(1u << (bit % 8));
		}
		CHECK(all_seen);
		// A shorter or longer packet with the same leading bytes is another packet (a trimmed or grown payload)
		if (size > 0)
			CHECK(kmodb::hash_payload(bytes.data(), size - 1) != original);
		std::vector<uint8_t> longer = bytes;
		longer.push_back(0);
		CHECK(kmodb::hash_payload(longer.data(), size + 1) != original);
	}
	// Swapping two words of one packet is an edit too, and zero bytes of different counts differ
	std::vector<uint8_t> a(64, 0), b(64, 0);
	a[0] = 1;
	b[8] = 1;
	CHECK(kmodb::hash_payload(a.data(), 64) != kmodb::hash_payload(b.data(), 64));
	CHECK(kmodb::hash_payload(a.data(), 40) != kmodb::hash_payload(a.data(), 41));
	// No collisions among 200000 random packets of one size (a 64-bit hash: expected none)
	std::vector<uint64_t> seen;
	std::vector<uint8_t>  packet(228);
	for (int i = 0; i < 200000; ++i)
	{
		for (uint8_t& byte : packet)
			byte = static_cast<uint8_t>(rng.next());
		seen.push_back(kmodb::hash_payload(packet.data(), 228));
	}
	std::sort(seen.begin(), seen.end());
	CHECK(std::adjacent_find(seen.begin(), seen.end()) == seen.end());

	// Speed: it runs twice per packet, so it has to be far below the cost of the rest of a packet (FNV-1a took 384 ns at 228 bytes)
	std::vector<uint8_t> frame(228, 0x5A);
	volatile uint64_t	 sink  = 0;
	const auto			 t0	   = std::chrono::steady_clock::now();
	constexpr int		 kRuns = 2000000;
	for (int i = 0; i < kRuns; ++i)
	{
		frame[0] = static_cast<uint8_t>(i);
		sink	 = sink + kmodb::hash_payload(frame.data(), 228);
	}
	const double ns = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count() / kRuns;
	std::printf("  payload fingerprint: %.0f ns per 228-byte packet\n", ns);
	CHECK(ns < 150);
}

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
		{"the_abi_is_the_one_that_was_declared_stable", test_the_abi_is_the_one_that_was_declared_stable},
		{"the_embedded_module_for_the_running_kernel_is_chosen_by_its_vermagic",
		 test_the_embedded_module_for_the_running_kernel_is_chosen_by_its_vermagic},
		{"the_payload_fingerprint_sees_every_edit", test_the_payload_fingerprint_sees_every_edit},
		{"cost_per_packet", test_cost_per_packet},
	};
	return test::run_tests("kmod_vm", cases, argc, argv);
}
