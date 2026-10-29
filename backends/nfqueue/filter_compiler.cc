#include "filter_compiler.h"

#include <arpa/inet.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <utility>

namespace nfq {
namespace {
constexpr size_t kMaxClauses = 512;
constexpr size_t kMaxRules	 = 1024;

struct ParseError
{
	std::string message;
	uint32_t	position;
};

enum class TokenKind
{
	end,
	word,
	op_and,
	op_or,
	op_not,
	eq,
	ne,
	lparen,
	rparen,
};

struct Token
{
	TokenKind	kind;
	std::string text;
	uint32_t	position;
};

enum class Side
{
	src,
	dst,
	either,
};

enum class LeafKind
{
	proto_tcp,
	proto_udp,
	proto_ip,
	proto_ipv6,
	outbound,
	inbound,
	flag,
	addr,
	port,
	if_index,
};

struct Leaf
{
	LeafKind			  kind		= LeafKind::proto_ip;
	Side				  side		= Side::either;
	const char*			  flag_name = "";
	bool				  tcp_port	= true;
	uint32_t			  number	= 0;
	std::vector<uint32_t> addrs;
};

struct Node
{
	enum class Type
	{
		constant,
		leaf,
		negation,
		conjunction,
		disjunction,
	};
	Type			  type	= Type::constant;
	bool			  value = false;
	Leaf			  leaf;
	std::vector<Node> kids;
};

[[noreturn]] void fail(const std::string& message, uint32_t position)
{
	throw ParseError{message, position};
}

std::vector<Token> tokenize(const std::string& text)
{
	std::vector<Token> tokens;
	size_t			   index = 0;
	auto			   push	 = [&](TokenKind kind, std::string value, size_t start) {
		   tokens.push_back({kind, std::move(value), static_cast<uint32_t>(start)});
	};
	while (index < text.size())
	{
		const unsigned char c = static_cast<unsigned char>(text[index]);
		if (std::isspace(c))
		{
			++index;
			continue;
		}
		const size_t start = index;
		if (std::isalnum(c) || c == '_' || c == '.')
		{
			while (index < text.size() &&
				   (std::isalnum(static_cast<unsigned char>(text[index])) || text[index] == '_' || text[index] == '.'))
				++index;
			std::string word = text.substr(start, index - start);
			if (word == "and")
				push(TokenKind::op_and, word, start);
			else if (word == "or")
				push(TokenKind::op_or, word, start);
			else if (word == "not")
				push(TokenKind::op_not, word, start);
			else
				push(TokenKind::word, std::move(word), start);
			continue;
		}
		const char next = index + 1 < text.size() ? text[index + 1] : '\0';
		if (c == '&' && next == '&')
			push(TokenKind::op_and, "&&", start), index += 2;
		else if (c == '|' && next == '|')
			push(TokenKind::op_or, "||", start), index += 2;
		else if (c == '=' && next == '=')
			push(TokenKind::eq, "==", start), index += 2;
		else if (c == '!' && next == '=')
			push(TokenKind::ne, "!=", start), index += 2;
		else if (c == '!')
			push(TokenKind::op_not, "!", start), ++index;
		else if (c == '(')
			push(TokenKind::lparen, "(", start), ++index;
		else if (c == ')')
			push(TokenKind::rparen, ")", start), ++index;
		else
			fail(std::string("unexpected character '") + static_cast<char>(c) + "'", static_cast<uint32_t>(start));
	}
	push(TokenKind::end, "", text.size());
	return tokens;
}

uint32_t parse_number(const Token& token, uint32_t maximum, const char* what)
{
	char*			   end	 = nullptr;
	const unsigned long value = std::strtoul(token.text.c_str(), &end, 0);
	if (token.text.empty() || !std::isdigit(static_cast<unsigned char>(token.text[0])) || *end != '\0' || value > maximum)
		fail(std::string("invalid ") + what + " '" + token.text + "'", token.position);
	return static_cast<uint32_t>(value);
}

uint32_t parse_ipv4(const Token& token)
{
	in_addr address{};
	if (inet_pton(AF_INET, token.text.c_str(), &address) != 1)
		fail("invalid IPv4 address '" + token.text + "'", token.position);
	return ntohl(address.s_addr);
}

std::string format_ipv4(uint32_t address)
{
	char buffer[16];
	std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", (address >> 24) & 0xFF, (address >> 16) & 0xFF, (address >> 8) & 0xFF, address & 0xFF);
	return buffer;
}

Node make_leaf(Leaf leaf)
{
	Node node;
	node.type = Node::Type::leaf;
	node.leaf = std::move(leaf);
	return node;
}

Node make_negation(Node kid)
{
	Node node;
	node.type = Node::Type::negation;
	node.kids.push_back(std::move(kid));
	return node;
}

class Parser
{
public:
	explicit Parser(std::vector<Token> tokens) : tokens_(std::move(tokens)) {}

	Node parse()
	{
		Node root = parse_or();
		if (peek().kind != TokenKind::end)
			fail("unexpected '" + peek().text + "'", peek().position);
		return root;
	}

private:
	const Token& peek() const { return tokens_[index_]; }
	Token		 take() { return tokens_[index_++]; }

	Node parse_or()
	{
		Node first = parse_and();
		if (peek().kind != TokenKind::op_or)
			return first;
		Node node;
		node.type = Node::Type::disjunction;
		node.kids.push_back(std::move(first));
		while (peek().kind == TokenKind::op_or)
		{
			take();
			node.kids.push_back(parse_and());
		}
		merge_address_alternatives(node);
		return node;
	}

	Node parse_and()
	{
		Node first = parse_unary();
		if (peek().kind != TokenKind::op_and)
			return first;
		Node node;
		node.type = Node::Type::conjunction;
		node.kids.push_back(std::move(first));
		while (peek().kind == TokenKind::op_and)
		{
			take();
			node.kids.push_back(parse_unary());
		}
		return node;
	}

	Node parse_unary()
	{
		if (peek().kind == TokenKind::op_not)
		{
			take();
			return make_negation(parse_unary());
		}
		if (peek().kind == TokenKind::lparen)
		{
			take();
			Node inner = parse_or();
			if (peek().kind != TokenKind::rparen)
				fail("expected ')'", peek().position);
			take();
			return inner;
		}
		return parse_atom();
	}

	// Server lists arrive as `ip.Addr == a or ip.Addr == b ...`; one set match keeps the rule count linear.
	static void merge_address_alternatives(Node& node)
	{
		std::vector<Node> merged;
		for (Node& kid : node.kids)
		{
			bool combined = false;
			if (kid.type == Node::Type::leaf && kid.leaf.kind == LeafKind::addr)
			{
				for (Node& existing : merged)
				{
					if (existing.type == Node::Type::leaf && existing.leaf.kind == LeafKind::addr && existing.leaf.side == kid.leaf.side)
					{
						existing.leaf.addrs.insert(existing.leaf.addrs.end(), kid.leaf.addrs.begin(), kid.leaf.addrs.end());
						combined = true;
						break;
					}
				}
			}
			if (!combined)
				merged.push_back(std::move(kid));
		}
		node.kids = std::move(merged);
		if (node.kids.size() == 1)
		{
			Node only = std::move(node.kids.front());
			node	  = std::move(only);
		}
	}

	Node parse_atom()
	{
		const Token token = take();
		if (token.kind != TokenKind::word)
			fail("expected a filter term, found '" + token.text + "'", token.position);
		const std::string& name = token.text;

		Leaf leaf;
		if (name == "true" || name == "false")
		{
			Node node;
			node.value = name == "true";
			return node;
		}
		if (name == "tcp")
			leaf.kind = LeafKind::proto_tcp;
		else if (name == "udp")
			leaf.kind = LeafKind::proto_udp;
		else if (name == "ip")
			leaf.kind = LeafKind::proto_ip;
		else if (name == "ipv6")
			leaf.kind = LeafKind::proto_ipv6;
		else if (name == "outbound")
			leaf.kind = LeafKind::outbound;
		else if (name == "inbound")
			leaf.kind = LeafKind::inbound;
		else if (const char* flag = tcp_flag(name))
		{
			leaf.kind	   = LeafKind::flag;
			leaf.flag_name = flag;
			if (peek().kind == TokenKind::eq || peek().kind == TokenKind::ne)
			{
				const bool	negate = take().kind == TokenKind::ne;
				const Token value  = take();
				const uint32_t bit = parse_number(value, 1, "flag value");
				Node		   node = make_leaf(leaf);
				return negate == (bit == 1) ? make_negation(std::move(node)) : node;
			}
		}
		else if (name == "ip.SrcAddr" || name == "ip.DstAddr" || name == "ip.Addr")
		{
			leaf.kind = LeafKind::addr;
			leaf.side = name == "ip.SrcAddr" ? Side::src : name == "ip.DstAddr" ? Side::dst : Side::either;
			const bool negate = parse_comparison(name);
			leaf.addrs.push_back(parse_ipv4(take()));
			return negate ? make_negation(make_leaf(leaf)) : make_leaf(leaf);
		}
		else if (name == "tcp.SrcPort" || name == "tcp.DstPort" || name == "udp.SrcPort" || name == "udp.DstPort")
		{
			leaf.kind	  = LeafKind::port;
			leaf.tcp_port = name[0] == 't';
			leaf.side	  = name.find("Src") != std::string::npos ? Side::src : Side::dst;
			const bool negate = parse_comparison(name);
			leaf.number		  = parse_number(take(), 65535, "port");
			return negate ? make_negation(make_leaf(leaf)) : make_leaf(leaf);
		}
		else if (name == "ifIdx")
		{
			leaf.kind		  = LeafKind::if_index;
			const bool negate = parse_comparison(name);
			leaf.number		  = parse_number(take(), 0xFFFFFFFFu, "interface index");
			return negate ? make_negation(make_leaf(leaf)) : make_leaf(leaf);
		}
		else
			fail("unsupported filter term '" + name + "'", token.position);
		return make_leaf(leaf);
	}

	bool parse_comparison(const std::string& name)
	{
		const Token op = take();
		if (op.kind != TokenKind::eq && op.kind != TokenKind::ne)
			fail("only == and != are supported for " + name, op.position);
		return op.kind == TokenKind::ne;
	}

	static const char* tcp_flag(const std::string& name)
	{
		static const std::pair<const char*, const char*> flags[] = {
			{"tcp.Fin", "fin"}, {"tcp.Syn", "syn"}, {"tcp.Rst", "rst"}, {"tcp.Psh", "psh"}, {"tcp.Ack", "ack"}, {"tcp.Urg", "urg"}};
		for (const auto& entry : flags)
			if (name == entry.first)
				return entry.second;
		return nullptr;
	}

	std::vector<Token> tokens_;
	size_t			   index_ = 0;
};

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

void emit_rules(const Clause& clause, bool forward, std::vector<CompiledRule>& rules)
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

bool compile_filter(const std::string& filter, bool forward, std::vector<CompiledRule>& rules, std::string& error, uint32_t& position)
{
	rules.clear();
	try
	{
		Node root;
		if (filter.find_first_not_of(" \t\r\n") == std::string::npos)
			root.value = true;
		else
			root = Parser(tokenize(filter)).parse();
		for (const Clause& clause : to_dnf(root, false))
			emit_rules(clause, forward, rules);
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
