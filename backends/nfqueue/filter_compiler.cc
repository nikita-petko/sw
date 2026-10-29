#include "filter_compiler.h"

#include <cstdio>
#include <utility>

#include "filter_ast.h"

namespace nfq {
namespace {
constexpr size_t kMaxClauses = 512;
constexpr size_t kMaxRules	 = 1024;

std::string format_ipv4(uint32_t address)
{
	char buffer[16];
	std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", (address >> 24) & 0xFF, (address >> 16) & 0xFF, (address >> 8) & 0xFF, address & 0xFF);
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
	dir_any	  = 0,
	dir_out	  = 1,
	dir_in	  = 2,
};

/// A conjunction of literals; contradictions are detected while building so impossible clauses never become rules.
struct Clause
{
	int									   dir		 = dir_any;
	int									   proto	 = proto_any;
	int									   proto_neg = 0;
	std::vector<std::string>			   matches;
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
			clause.matches.push_back(std::string("tcp flags & ") + leaf.flag_name + (negated ? " == 0" : std::string(" == ") + leaf.flag_name));
			return true;
		case LeafKind::addr:
		{
			const std::string set = address_set(leaf.addrs);
			const char*		  op  = negated ? " != " : " ";
			if (leaf.side != Side::dst)
				clause.matches.push_back(std::string("ip saddr") + op + set);
			if (leaf.side != Side::src)
				clause.matches.push_back(std::string("ip daddr") + op + set);
			return true;
		}
		case LeafKind::port:
			if (!require_proto(clause, leaf.tcp_port ? proto_tcp : proto_udp))
				return false;
			clause.matches.push_back(std::string(leaf.tcp_port ? "tcp " : "udp ") + (leaf.side == Side::src ? "sport" : "dport") +
									 (negated ? " != " : " ") + std::to_string(leaf.number));
			return true;
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

std::string interface_match(Hook hook, bool use_output_interface, uint32_t index, bool negated)
{
	(void)hook;
	return std::string("meta ") + (use_output_interface ? "oif" : "iif") + (negated ? " != " : " ") + std::to_string(index);
}

void emit_rules(const Clause& clause, bool forward, bool include_forward, std::vector<CompiledRule>& rules)
{
	std::string base = "meta nfproto ipv4";
	if (clause.proto == proto_tcp)
		base += " ip protocol tcp";
	else if (clause.proto == proto_udp)
		base += " ip protocol udp";
	if ((clause.proto_neg & proto_tcp) != 0)
		base += " ip protocol != tcp";
	if ((clause.proto_neg & proto_udp) != 0)
		base += " ip protocol != udp";
	for (const std::string& match : clause.matches)
		base += " " + match;

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
		std::vector<std::string> variants{base};
		for (const auto& [index, negated] : clause.interfaces)
		{
			std::vector<std::string> next;
			for (const std::string& variant : variants)
			{
				if (hook == Hook::forward)
				{
					if (negated)
						next.push_back(variant + " " + interface_match(hook, false, index, true) + " " + interface_match(hook, true, index, true));
					else
					{
						next.push_back(variant + " " + interface_match(hook, false, index, false));
						next.push_back(variant + " " + interface_match(hook, true, index, false));
					}
				}
				else
					next.push_back(variant + " " + interface_match(hook, hook == Hook::output, index, negated));
			}
			variants = std::move(next);
		}
		for (std::string& variant : variants)
		{
			rules.push_back({hook, std::move(variant)});
			if (rules.size() > kMaxRules)
				fail("filter is too complex (expands to more than " + std::to_string(kMaxRules) + " rules)", 0);
		}
	}
}
}  // namespace

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

bool compile_filter(const std::string& filter,
					bool			 forward,
					std::vector<CompiledRule>& rules,
					std::string&	 error,
					uint32_t&		 position,
					bool			 include_forward)
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
}  // namespace nfq
