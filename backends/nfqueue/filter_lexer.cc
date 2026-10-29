#include "filter_ast.h"

#include <cctype>
#include <utility>

namespace nfq {

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

}  // namespace nfq
