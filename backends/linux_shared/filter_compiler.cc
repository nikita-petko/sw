#include "filter_compiler.h"

#include <cstdio>
#include <initializer_list>
#include <utility>

#include "filter_ast.h"

namespace linux_shared {
namespace {
	constexpr size_t kMaxClauses = 512;
	constexpr size_t kMaxRules	 = 1024;

	std::string format_ipv4(uint32_t address)
	{
		char buffer[16];
		std::snprintf(buffer,
					  sizeof(buffer),
					  "%u.%u.%u.%u",
					  (address >> 24) & 0xFF,
					  (address >> 16) & 0xFF,
					  (address >> 8) & 0xFF,
					  address & 0xFF);
		return buffer;
	}

	enum Proto : int
	{
		proto_any = 0,
		proto_tcp = 1,
		proto_udp = 2,
	};

	enum Direction : int
	{
		dir_any = 0,
		dir_out = 1,
		dir_in	= 2,
	};

	/// A conjunction of literals; contradictions are detected while building so impossible clauses never become rules.
	struct Clause
	{
		int									   dir		 = dir_any;
		int									   proto	 = proto_any;
		int									   proto_neg = 0;
		std::vector<Match>					   matches;
		std::vector<std::pair<uint32_t, bool>> interfaces;
	};

	bool require_proto(Clause& clause, int proto)
	{
		if (clause.proto != proto_any && clause.proto != proto)
			return false;
		if ((clause.proto_neg & proto) != 0)
			return false;
		clause.proto = proto;
		return true;
	}

	bool set_direction(Clause& clause, int dir)
	{
		if (clause.dir != dir_any && clause.dir != dir)
			return false;
		clause.dir = dir;
		return true;
	}

	std::string address_set(const std::vector<uint32_t>& addrs)
	{
		std::string text = "{ ";
		for (size_t index = 0; index < addrs.size(); ++index)
		{
			if (index != 0)
				text += ", ";
			text += format_ipv4(addrs[index]);
		}
		return text + " }";
	}

	struct FlagBit
	{
		const char* name;
		uint8_t		bit;
	};

	constexpr FlagBit kFlagBits[] = {{"fin", 0x01}, {"syn", 0x02}, {"rst", 0x04}, {"psh", 0x08}, {"ack", 0x10}, {"urg", 0x20}};

	uint8_t flag_bit(const std::string& name)
	{
		for (const FlagBit& flag : kFlagBits)
			if (name == flag.name)
				return flag.bit;
		fail("unsupported TCP flag '" + name + "'", 0);
	}

	Match protocol_match(Transport transport, bool negated)
	{
		Match match;
		match.kind		= MatchKind::ip_protocol;
		match.transport = transport;
		match.negated	= negated;
		return match;
	}

	bool apply_literal(Clause& clause, const Leaf& leaf, bool negated)
	{
		switch (leaf.kind)
		{
			case LeafKind::proto_tcp:
			case LeafKind::proto_udp:
				{
					const int proto = leaf.kind == LeafKind::proto_tcp ? proto_tcp : proto_udp;
					if (!negated)
						return require_proto(clause, proto);
					if (clause.proto == proto)
						return false;
					clause.proto_neg |= proto;
					return true;
				}
			case LeafKind::proto_ip:
				return !negated;
			case LeafKind::proto_ipv6:
				return negated;
			case LeafKind::outbound:
				return set_direction(clause, negated ? dir_in : dir_out);
			case LeafKind::inbound:
				return set_direction(clause, negated ? dir_out : dir_in);
			case LeafKind::flag:
				if (!require_proto(clause, proto_tcp))
					return false;
				{
					Match match;
					match.kind	   = MatchKind::tcp_flag;
					match.tcp_flag = flag_bit(leaf.flag_name);
					match.negated  = negated;
					clause.matches.push_back(std::move(match));
					return true;
				}
			case LeafKind::addr:
				{
					Match match;
					match.kind	  = MatchKind::ip_addr;
					match.negated = negated;
					match.addrs	  = leaf.addrs;
					if (leaf.side != Side::dst)
					{
						match.endpoint = Endpoint::source;
						clause.matches.push_back(match);
					}
					if (leaf.side != Side::src)
					{
						match.endpoint = Endpoint::destination;
						clause.matches.push_back(match);
					}
					return true;
				}
			case LeafKind::port:
				if (!require_proto(clause, leaf.tcp_port ? proto_tcp : proto_udp))
					return false;
				{
					if (leaf.number > 0xFFFF)
						fail("port out of range", 0);
					Match match;
					match.kind		= MatchKind::port;
					match.negated	= negated;
					match.transport = leaf.tcp_port ? Transport::tcp : Transport::udp;
					match.endpoint	= leaf.side == Side::src ? Endpoint::source : Endpoint::destination;
					match.port		= static_cast<uint16_t>(leaf.number);
					clause.matches.push_back(std::move(match));
					return true;
				}
			case LeafKind::if_index:
				clause.interfaces.emplace_back(leaf.number, negated);
				return true;
		}
		return false;
	}

	bool merge_clauses(const Clause& left, const Clause& right, Clause& out)
	{
		out = left;
		if (right.dir != dir_any && !set_direction(out, right.dir))
			return false;
		if (right.proto != proto_any && !require_proto(out, right.proto))
			return false;
		if ((right.proto_neg & out.proto) != 0 && out.proto != proto_any)
			return false;
		out.proto_neg |= right.proto_neg;
		out.matches.insert(out.matches.end(), right.matches.begin(), right.matches.end());
		out.interfaces.insert(out.interfaces.end(), right.interfaces.begin(), right.interfaces.end());
		return true;
	}

	using Clauses = std::vector<Clause>;

	void check_clause_count(size_t count)
	{
		if (count > kMaxClauses)
			fail("filter is too complex (expands to more than " + std::to_string(kMaxClauses) + " rules)", 0);
	}

	Clauses to_dnf(const Node& node, bool negated)
	{
		switch (node.type)
		{
			case Node::Type::constant:
				return node.value != negated ? Clauses{Clause{}} : Clauses{};
			case Node::Type::negation:
				return to_dnf(node.kids.front(), !negated);
			case Node::Type::leaf:
				{
					if (node.leaf.kind == LeafKind::addr && node.leaf.side == Side::either && !negated)
					{
						Leaf source = node.leaf;
						Leaf dest	= node.leaf;
						source.side = Side::src;
						dest.side	= Side::dst;
						Clause first, second;
						apply_literal(first, source, false);
						apply_literal(second, dest, false);
						return {first, second};
					}
					Clause clause;
					return apply_literal(clause, node.leaf, negated) ? Clauses{clause} : Clauses{};
				}
			case Node::Type::conjunction:
			case Node::Type::disjunction:
				{
					const bool as_and = (node.type == Node::Type::conjunction) != negated;
					if (!as_and)
					{
						Clauses result;
						for (const Node& kid : node.kids)
						{
							Clauses part = to_dnf(kid, negated);
							result.insert(result.end(), part.begin(), part.end());
							check_clause_count(result.size());
						}
						return result;
					}
					Clauses result{Clause{}};
					for (const Node& kid : node.kids)
					{
						const Clauses part = to_dnf(kid, negated);
						Clauses		  next;
						for (const Clause& left : result)
						{
							for (const Clause& right : part)
							{
								Clause merged;
								if (merge_clauses(left, right, merged))
									next.push_back(std::move(merged));
							}
							check_clause_count(next.size());
						}
						result = std::move(next);
					}
					return result;
				}
		}
		return {};
	}

	Match interface_match(bool use_output_interface, uint32_t index, bool negated)
	{
		Match match;
		match.kind	  = MatchKind::interface;
		match.output  = use_output_interface;
		match.index	  = index;
		match.negated = negated;
		return match;
	}

	std::string render_rule(const std::vector<Match>& matches)
	{
		std::string text;
		for (const Match& match : matches)
		{
			if (!text.empty())
				text += ' ';
			text += render_match(match);
		}
		return text;
	}

	void emit_rules(const Clause& clause, bool forward, bool include_forward, std::vector<CompiledRule>& rules)
	{
		std::vector<Match> base(1);
		if (clause.proto == proto_tcp)
			base.push_back(protocol_match(Transport::tcp, false));
		else if (clause.proto == proto_udp)
			base.push_back(protocol_match(Transport::udp, false));
		if ((clause.proto_neg & proto_tcp) != 0)
			base.push_back(protocol_match(Transport::tcp, true));
		if ((clause.proto_neg & proto_udp) != 0)
			base.push_back(protocol_match(Transport::udp, true));
		base.insert(base.end(), clause.matches.begin(), clause.matches.end());

		std::vector<Hook> hooks;
		if (forward)
		{
			// In the forward path every packet is considered outbound.
			if (clause.dir == dir_in)
				return;
			hooks = {Hook::forward};
		}
		else if (clause.dir == dir_out)
			hooks = {Hook::output};
		else if (clause.dir == dir_in)
			hooks = {Hook::input};
		else
			hooks = {Hook::input, Hook::output};
		if (include_forward && !forward && clause.dir != dir_in)
			hooks.push_back(Hook::forward);

		for (Hook hook : hooks)
		{
			std::vector<std::vector<Match>> variants{base};
			for (const auto& [index, negated] : clause.interfaces)
			{
				std::vector<std::vector<Match>> next;
				const auto						extend = [&next](const std::vector<Match>& variant, std::initializer_list<Match> extra) {
					next.push_back(variant);
					next.back().insert(next.back().end(), extra.begin(), extra.end());
				};
				for (const std::vector<Match>& variant : variants)
				{
					if (hook == Hook::forward)
					{
						if (negated)
							extend(variant, {interface_match(false, index, true), interface_match(true, index, true)});
						else
						{
							extend(variant, {interface_match(false, index, false)});
							extend(variant, {interface_match(true, index, false)});
						}
					}
					else
						extend(variant, {interface_match(hook == Hook::output, index, negated)});
				}
				variants = std::move(next);
			}
			for (std::vector<Match>& variant : variants)
			{
				std::string text = render_rule(variant);
				rules.push_back({hook, std::move(text), std::move(variant)});
				if (rules.size() > kMaxRules)
					fail("filter is too complex (expands to more than " + std::to_string(kMaxRules) + " rules)", 0);
			}
		}
	}
}  // namespace

const char* tcp_flag_name(uint8_t flag)
{
	for (const FlagBit& entry : kFlagBits)
		if (entry.bit == flag)
			return entry.name;
	return "";
}

std::string render_match(const Match& match)
{
	const char* op = match.negated ? " != " : " ";
	switch (match.kind)
	{
		case MatchKind::nfproto_ipv4:
			return "meta nfproto ipv4";
		case MatchKind::ip_protocol:
			return std::string("ip protocol") + op + (match.transport == Transport::tcp ? "tcp" : "udp");
		case MatchKind::tcp_flag:
			return std::string("tcp flags & ") + tcp_flag_name(match.tcp_flag) +
				   (match.negated ? " == 0" : std::string(" == ") + tcp_flag_name(match.tcp_flag));
		case MatchKind::ip_addr:
			return std::string(match.endpoint == Endpoint::source ? "ip saddr" : "ip daddr") + op + address_set(match.addrs);
		case MatchKind::port:
			return std::string(match.transport == Transport::tcp ? "tcp " : "udp ") +
				   (match.endpoint == Endpoint::source ? "sport" : "dport") + op + std::to_string(match.port);
		case MatchKind::interface:
			return std::string("meta ") + (match.output ? "oif" : "iif") + op + std::to_string(match.index);
	}
	return "";
}

const char* hook_name(Hook hook)
{
	switch (hook)
	{
		case Hook::input:
			return "input";
		case Hook::output:
			return "output";
		case Hook::forward:
			return "forward";
	}
	return "input";
}

bool compile_filter(const std::string&		   filter,
					bool					   forward,
					std::vector<CompiledRule>& rules,
					std::string&			   error,
					uint32_t&				   position,
					bool					   include_forward)
{
	rules.clear();
	try
	{
		Node root;
		if (filter.find_first_not_of(" \t\r\n") == std::string::npos)
			root.value = true;
		else
			root = parse_filter(filter);
		for (const Clause& clause : to_dnf(root, false))
			emit_rules(clause, forward, include_forward, rules);
		return true;
	}
	catch (const ParseError& failure)
	{
		rules.clear();
		error	 = failure.message;
		position = failure.position;
		return false;
	}
}
}  // namespace linux_shared
