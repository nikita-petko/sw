#ifndef NET_MONITOR_JSON_H_
#define NET_MONITOR_JSON_H_

#include <cstdio>
#include <string>

namespace net_monitor_json {

/// Escapes text for use inside a JSON string literal.
inline std::string escape(const std::string& text)
{
	std::string out;
	for (const char c : text)
	{
		switch (c)
		{
			case '"': out += "\\\""; break;
			case '\\': out += "\\\\"; break;
			case '\n': out += "\\n"; break;
			case '\r': out += "\\r"; break;
			case '\t': out += "\\t"; break;
			default:
				if (static_cast<unsigned char>(c) < 0x20)
				{
					char escaped[8];
					std::snprintf(escaped, sizeof(escaped), "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
					out += escaped;
				}
				else
					out += c;
		}
	}
	return out;
}

}  // namespace net_monitor_json

#endif
