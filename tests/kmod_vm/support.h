// Helpers shared by the unit tests and the fuzz harness of the swdivert filter VM: a packet builder, random packet and filter generators
// and a reference evaluator that reads a filter's syntax tree directly (no clauses, no sets, no instructions) so that it can be compared
// with the compiled program.
#ifndef TESTS_KMOD_VM_SUPPORT_H_
#define TESTS_KMOD_VM_SUPPORT_H_

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "filter_ast.h"
#include "filter_program.h"
#include "swdivert_vm.h"

namespace vmtest {

struct Rng
{
	uint64_t state;
	explicit Rng(uint64_t seed) : state(seed * 2862933555777941757ull + 3037000493ull) {}
	uint64_t next()
	{
		state ^= state << 13;
		state ^= state >> 7;
		state ^= state << 17;
		return state;
	}
	uint32_t below(uint32_t limit) { return limit == 0 ? 0 : static_cast<uint32_t>(next() % limit); }
	bool	 chance(uint32_t percent) { return below(100) < percent; }
};

using Bytes = std::vector<uint8_t>;

inline void put16(Bytes& b, size_t off, uint32_t v)
{
	b[off]	   = static_cast<uint8_t>(v >> 8);
	b[off + 1] = static_cast<uint8_t>(v);
}
inline void put32(Bytes& b, size_t off, uint32_t v)
{
	put16(b, off, v >> 16);
	put16(b, off + 2, v & 0xFFFF);
}

struct PacketSpec
{
	uint8_t	 proto		= 17;
	uint32_t src		= 0x0A0A0102;
	uint32_t dst		= 0x0A0A0202;
	uint32_t sport		= 1000;
	uint32_t dport		= 9000;
	uint8_t	 ttl		= 64;
	uint32_t frag		= 0;  // flags and offset word
	unsigned ip_options = 0;  // in 4-byte units
	uint8_t	 tcp_flags	= 0x10;
	unsigned tcp_doff	= 5;
	Bytes	 payload;
};

// A well-formed packet for the spec (lengths consistent, no checksums: the VM does not look at them)
inline Bytes build(const PacketSpec& s)
{
	const size_t ihl = 20 + s.ip_options * 4;
	// A TCP header always occupies at least its 20 fixed bytes, whatever the data-offset nibble claims (a nibble below 5 is how the tests
	// make a malformed header; it must not make the buffer too small to write the fixed fields into)
	const size_t l4_len = s.proto == 6 ? 20 + (s.tcp_doff > 5 ? (s.tcp_doff - 5) * 4 : 0) : s.proto == 17 ? 8 : 0;
	Bytes		 p(ihl + l4_len + s.payload.size(), 0);
	p[0] = static_cast<uint8_t>(0x40 | (ihl / 4));
	put16(p, 2, static_cast<uint32_t>(p.size()));
	put16(p, 6, s.frag);
	p[8] = s.ttl;
	p[9] = s.proto;
	put32(p, 12, s.src);
	put32(p, 16, s.dst);
	if (s.proto == 6 || s.proto == 17)
	{
		put16(p, ihl, s.sport);
		put16(p, ihl + 2, s.dport);
	}
	if (s.proto == 6)
	{
		p[ihl + 12] = static_cast<uint8_t>(s.tcp_doff << 4);
		p[ihl + 13] = s.tcp_flags;
	}
	if (s.proto == 17)
		put16(p, ihl + 4, static_cast<uint32_t>(8 + s.payload.size()));
	std::copy(s.payload.begin(), s.payload.end(), p.begin() + static_cast<long>(ihl + l4_len));
	return p;
}

struct Meta
{
	uint32_t in_ifindex	 = 2;
	uint32_t out_ifindex = 3;
	uint32_t mark		 = 0;
	uint8_t	 hook		 = 2;  // NF_INET_*: 1 LOCAL_IN, 2 FORWARD, 3 LOCAL_OUT
};

// What the hook hands the VM: the first 256 bytes and the real length
inline swdiv_vm_ctx context(const Bytes& packet, const Meta& meta)
{
	swdiv_vm_ctx ctx = {};
	ctx.pkt			 = packet.data();
	ctx.len			 = static_cast<uint32_t>(std::min<size_t>(packet.size(), SWDIV_VM_PREFIX));
	ctx.total_len	 = static_cast<uint32_t>(packet.size());
	ctx.in_ifindex	 = meta.in_ifindex;
	ctx.out_ifindex	 = meta.out_ifindex;
	ctx.mark		 = meta.mark;
	ctx.hook		 = meta.hook;
	ctx.outbound	 = meta.hook != 1;
	return ctx;
}

inline bool run(const kmodf::Program& program, const Bytes& packet, const Meta& meta = {})
{
	const std::vector<swdiv_vm_set> sets = kmodf::vm_sets(program);
	const swdiv_vm_ctx				ctx	 = context(packet, meta);
	return swdiv_vm_run(program.insns.data(),
						static_cast<uint32_t>(program.insns.size()),
						sets.data(),
						static_cast<uint32_t>(sets.size()),
						&ctx) != 0;
}

// ---- random packets ----

// The values the generators draw from. Small pools make packets and filters hit each other; a rig that needs real addresses or interface
// indexes (the kernel check of swbench) replaces them.
inline std::vector<uint32_t>& addr_pool()
{
	static std::vector<uint32_t> pool = {0x0A0A0101, 0x0A0A0102, 0x0A0A0201, 0x0A0A0202, 0x0A0A0303, 0xC0A80001};
	return pool;
}
inline std::vector<uint32_t>& port_pool()
{
	static std::vector<uint32_t> pool = {80, 443, 9000, 9001, 53, 12345};
	return pool;
}
inline std::vector<uint32_t>& if_pool()
{
	static std::vector<uint32_t> pool = {1, 2, 3, 4};
	return pool;
}
inline uint32_t pick(Rng& rng, const std::vector<uint32_t>& pool)
{
	return pool[rng.below(static_cast<uint32_t>(pool.size()))];
}

// A mostly valid IPv4 packet with the odd inconsistency: truncation, wrong total length, odd header lengths, later fragments.
inline Bytes random_packet(Rng& rng)
{
	PacketSpec			 spec;
	static const uint8_t protos[] = {6, 6, 6, 17, 17, 17, 1, 47};
	spec.proto					  = protos[rng.below(8)];
	spec.src					  = rng.chance(85) ? pick(rng, addr_pool()) : static_cast<uint32_t>(rng.next());
	spec.dst					  = rng.chance(85) ? pick(rng, addr_pool()) : static_cast<uint32_t>(rng.next());
	spec.sport					  = rng.chance(85) ? pick(rng, port_pool()) : rng.below(65536);
	spec.dport					  = rng.chance(85) ? pick(rng, port_pool()) : rng.below(65536);
	spec.ttl					  = static_cast<uint8_t>(rng.below(256));
	spec.ip_options				  = rng.chance(20) ? rng.below(4) : 0;
	spec.tcp_flags				  = static_cast<uint8_t>(rng.below(64));
	spec.tcp_doff				  = rng.chance(90) ? 5 + rng.below(3) : rng.below(5);  // sometimes a header that is too short
	spec.frag					  = rng.chance(85) ? 0 : (rng.chance(50) ? 0x2000 : rng.below(0x4000));
	spec.payload.resize(rng.chance(80) ? rng.below(80) : rng.below(400));
	for (uint8_t& byte : spec.payload)
		byte = static_cast<uint8_t>(rng.next());
	Bytes p = build(spec);
	if (rng.chance(8) && p.size() > 20)
		put16(p, 2, rng.below(static_cast<uint32_t>(p.size() + 40)));  // a wrong total length
	if (rng.chance(8) && p.size() > 21)
		p.resize(20 + rng.below(static_cast<uint32_t>(p.size() - 20)));	 // cut short
	return p;
}

// ---- random filters (text) ----

inline std::string address_text(uint32_t a)
{
	return std::to_string(a >> 24) + "." + std::to_string((a >> 16) & 255) + "." + std::to_string((a >> 8) & 255) + "." +
		   std::to_string(a & 255);
}

inline std::string random_term(Rng& rng)
{
	switch (rng.below(14))
	{
		case 0:
			return "tcp";
		case 1:
			return "udp";
		case 2:
			return rng.chance(80) ? "ip" : "ipv6";
		case 3:
			return rng.chance(50) ? "outbound" : "inbound";
		case 4:
			{
				static const char* flags[] = {"tcp.Syn", "tcp.Ack", "tcp.Fin", "tcp.Rst", "tcp.Psh", "tcp.Urg"};
				std::string		   term	   = flags[rng.below(6)];
				if (rng.chance(50))
					term += std::string(rng.chance(50) ? " == " : " != ") + (rng.chance(50) ? "0" : "1");
				return term;
			}
		case 5:
		case 6:
			{
				static const char* names[] = {"ip.SrcAddr", "ip.DstAddr", "ip.Addr"};
				return std::string(names[rng.below(3)]) + (rng.chance(75) ? " == " : " != ") + address_text(pick(rng, addr_pool()));
			}
		case 7:
			{
				// A list of addresses, the shape of a server list: becomes one set
				static const char* names[] = {"ip.SrcAddr", "ip.DstAddr", "ip.Addr"};
				const std::string  name	   = names[rng.below(3)];
				std::string		   text	   = "(";
				const unsigned	   count   = 2 + rng.below(4);
				for (unsigned i = 0; i < count; ++i)
					text += (i ? " or " : "") + name + " == " + address_text(pick(rng, addr_pool()));
				return text + ")";
			}
		case 8:
		case 9:
		case 10:
			{
				static const char* names[] = {"tcp.SrcPort", "tcp.DstPort", "udp.SrcPort", "udp.DstPort"};
				return std::string(names[rng.below(4)]) + (rng.chance(75) ? " == " : " != ") + std::to_string(pick(rng, port_pool()));
			}
		case 11:
			return std::string("ifIdx ") + (rng.chance(75) ? "== " : "!= ") + std::to_string(pick(rng, if_pool()));
		case 12:
			return rng.chance(50) ? "true" : "false";
		default:
			return "tcp.DstPort == " + std::to_string(rng.below(65536));
	}
}

inline std::string random_filter(Rng& rng, unsigned depth)
{
	if (depth == 0 || rng.chance(30))
		return random_term(rng);
	if (rng.chance(15))
		return "not (" + random_filter(rng, depth - 1) + ")";
	const std::string joiner = rng.chance(50) ? " and " : " or ";
	std::string		  text	 = "(" + random_filter(rng, depth - 1);
	const unsigned	  count	 = 1 + rng.below(3);
	for (unsigned i = 0; i < count; ++i)
		text += joiner + random_filter(rng, depth - 1);
	return text + ")";
}

// ---- reference evaluator ----

// The packet as the documented semantics see it (kmod/include/swdivert_abi.h): which fields exist and what they hold.
struct Facts
{
	bool	 ipv4  = false;
	uint32_t proto = 0, src = 0, dst = 0;
	bool	 has_ports = false, has_flags = false;
	uint32_t sport = 0, dport = 0, flags = 0;
	Meta	 meta;
};

inline Facts facts_of(const Bytes& packet, const Meta& meta)
{
	Facts f;
	f.meta				   = meta;
	const size_t available = std::min<size_t>(packet.size(), SWDIV_VM_PREFIX);
	if (available < 20 || (packet[0] >> 4) != 4)
		return f;
	const size_t ihl = static_cast<size_t>(packet[0] & 15) * 4;
	if (ihl < 20 || ihl > available)
		return f;
	const size_t total = (static_cast<size_t>(packet[2]) << 8) | packet[3];
	if (total < ihl)
		return f;
	f.ipv4			   = true;
	f.proto			   = packet[9];
	f.src			   = (static_cast<uint32_t>(packet[12]) << 24) | (static_cast<uint32_t>(packet[13]) << 16) |
						 (static_cast<uint32_t>(packet[14]) << 8) | packet[15];
	f.dst			   = (static_cast<uint32_t>(packet[16]) << 24) | (static_cast<uint32_t>(packet[17]) << 16) |
						 (static_cast<uint32_t>(packet[18]) << 8) | packet[19];
	const size_t end   = std::min(total, available);
	const bool	 first = (((static_cast<uint32_t>(packet[6]) << 8) | packet[7]) & 0x1FFF) == 0;
	if ((f.proto == 6 || f.proto == 17) && first && end >= ihl + 4)
	{
		f.has_ports = true;
		f.sport		= (static_cast<uint32_t>(packet[ihl]) << 8) | packet[ihl + 1];
		f.dport		= (static_cast<uint32_t>(packet[ihl + 2]) << 8) | packet[ihl + 3];
	}
	if (f.proto == 6 && first && end >= ihl + 14)
	{
		f.has_flags = true;
		f.flags		= packet[ihl + 13];
	}
	return f;
}

inline bool literal(const nfq::Leaf& leaf, bool negated, const Facts& f)
{
	using nfq::LeafKind;
	// Without a usable IP header none of its fields exist: a test of one fails, negated or not
	if (!f.ipv4 && (leaf.kind == LeafKind::proto_tcp || leaf.kind == LeafKind::proto_udp || leaf.kind == LeafKind::addr))
		return false;
	switch (leaf.kind)
	{
		case LeafKind::proto_tcp:
			return (f.proto == 6) != negated;
		case LeafKind::proto_udp:
			return (f.proto == 17) != negated;
		case LeafKind::proto_ip:
			return !negated;
		case LeafKind::proto_ipv6:
			return negated;
		case LeafKind::outbound:
			return !negated;  // on the forward path every packet is outbound
		case LeafKind::inbound:
			return negated;
		case LeafKind::flag:
			{
				// A field of an absent protocol never matches, negated or not
				if (!f.has_flags)
					return false;
				static const struct
				{
					const char* name;
					uint32_t	bit;
				} table[]	 = {{"fin", 1}, {"syn", 2}, {"rst", 4}, {"psh", 8}, {"ack", 16}, {"urg", 32}};
				uint32_t bit = 0;
				for (const auto& entry : table)
					if (std::string(leaf.flag_name) == entry.name)
						bit = entry.bit;
				return ((f.flags & bit) != 0) != negated;
			}
		case LeafKind::addr:
			{
				const bool src_in = std::find(leaf.addrs.begin(), leaf.addrs.end(), f.src) != leaf.addrs.end();
				const bool dst_in = std::find(leaf.addrs.begin(), leaf.addrs.end(), f.dst) != leaf.addrs.end();
				const bool hit	  = leaf.side == nfq::Side::src ? src_in : leaf.side == nfq::Side::dst ? dst_in : (src_in || dst_in);
				return hit != negated;
			}
		case LeafKind::port:
			{
				const uint32_t want_proto = leaf.tcp_port ? 6 : 17;
				if (f.proto != want_proto || !f.has_ports)
					return false;
				const uint32_t port = leaf.side == nfq::Side::src ? f.sport : f.dport;
				return (port == leaf.number) != negated;
			}
		case LeafKind::if_index:
			return (f.meta.in_ifindex == leaf.number || f.meta.out_ifindex == leaf.number) != negated;	// either interface
	}
	return false;
}

// Negations are pushed down to the literals the way the compiler does it (De Morgan), because a negated test of an absent field is not
// the opposite of the test: it is false as well.
inline bool reference(const nfq::Node& node, bool negated, const Facts& f)
{
	switch (node.type)
	{
		case nfq::Node::Type::constant:
			return node.value != negated;
		case nfq::Node::Type::negation:
			return reference(node.kids.front(), !negated, f);
		case nfq::Node::Type::leaf:
			return literal(node.leaf, negated, f);
		case nfq::Node::Type::conjunction:
		case nfq::Node::Type::disjunction:
			{
				const bool as_and = (node.type == nfq::Node::Type::conjunction) != negated;
				for (const nfq::Node& kid : node.kids)
				{
					const bool value = reference(kid, negated, f);
					if (as_and && !value)
						return false;
					if (!as_and && value)
						return true;
				}
				return as_and;
			}
	}
	return false;
}

}  // namespace vmtest

#endif
