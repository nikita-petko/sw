#ifndef NFQUEUE_FILTER_AST_H_
#define NFQUEUE_FILTER_AST_H_

#include <cstdint>
#include <string>
#include <vector>

/// Internal syntax tree shared by the filter lexer, parser and compiler (see filter_compiler.h for the public API).
namespace nfq {

/// Thrown while lexing, parsing or compiling a filter; compile_filter() turns it into an error message and position.
struct ParseError
{
	std::string message;
	uint32_t	position;
};

[[noreturn]] inline void fail(const std::string& message, uint32_t position)
{
	throw ParseError{message, position};
}

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

/// Splits filter text into tokens, ending with a TokenKind::end token. Throws ParseError.
std::vector<Token> tokenize(const std::string& text);
/// Parses filter text into a syntax tree. Throws ParseError.
Node parse_filter(const std::string& text);

}  // namespace nfq

#endif
