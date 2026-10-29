#include <arpa/inet.h>

#include <cctype>
#include <cstdlib>
#include <utility>

#include "filter_ast.h"

namespace nfq {
namespace {
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
}  // namespace

Node parse_filter(const std::string& text)
{
	return Parser(tokenize(text)).parse();
}

}  // namespace nfq
