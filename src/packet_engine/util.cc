#include "packet_engine_util.h"

#include <cstdio>
#include <string>

#include "log.h"
#include "platform.h"

LOG_DEFAULT_GROUP(logging::group::report)

std::string format_state_divider(size_t width, const std::string& label)
{
	const size_t inner_width = width - 2;
	if (label.empty())
		return "|" + std::string(inner_width, '-') + "|";

	const std::string text		 = " " + label + " ";
	const size_t	  left_width = (inner_width - text.size()) / 2;
	return "|" + std::string(left_width, '-') + text + std::string(inner_width - left_width - text.size(), '-') + "|";
}

std::string format_tcp_flags(const TcpHeader& tcp_header)
{
	std::string result;
	const auto	append = [&](const char* flag, bool enabled) {
		if (!enabled)
			return;
		if (!result.empty())
			result += ',';
		result += flag;
	};
	append("FIN", tcp_header.Fin);
	append("SYN", tcp_header.Syn);
	append("RST", tcp_header.Rst);
	append("PSH", tcp_header.Psh);
	append("ACK", tcp_header.Ack);
	append("URG", tcp_header.Urg);
	return result.empty() ? "-" : result;
}

// bright white, contrasts with the green LOG_INFO text around it
constexpr const char* kStatColor = "\033[97m";
// switches back to the green LOG_INFO color after a highlighted stat
constexpr const char* kStatReset = "\033[32m";

std::string highlight(const std::string& value)
{
	return std::string(kStatColor) + value + kStatReset;
}

size_t visible_length(const std::string& text)
{
	size_t length = 0;
	for (size_t index = 0; index < text.size(); ++index)
	{
		if (text[index] == '\033' && index + 1 < text.size() && text[index + 1] == '[')
		{
			index += 2;
			while (index < text.size() && text[index] != 'm')
				++index;
			continue;
		}
		++length;
	}
	return length;
}

void log_state_line(size_t width, const std::string& text)
{
	const size_t inner_width = width - 4;
	const size_t visible	 = visible_length(text);
	const size_t padding	 = visible < inner_width ? inner_width - visible : 0;
	LOG_INFO("| %s%*s |", text.c_str(), static_cast<int>(padding), "");
}

std::string format_ipv4_address(uint32_t address)
{
	const auto* bytes	   = reinterpret_cast<const unsigned char*>(&address);
	char		buffer[16] = {};
	std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
	return buffer;
}

std::string format_ipv6_address(const uint32_t* address)
{
	const auto* bytes	   = reinterpret_cast<const unsigned char*>(address);
	char		buffer[64] = {};
	std::snprintf(buffer,
				  sizeof(buffer),
				  "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
				  bytes[0],
				  bytes[1],
				  bytes[2],
				  bytes[3],
				  bytes[4],
				  bytes[5],
				  bytes[6],
				  bytes[7],
				  bytes[8],
				  bytes[9],
				  bytes[10],
				  bytes[11],
				  bytes[12],
				  bytes[13],
				  bytes[14],
				  bytes[15]);
	return buffer;
}

PacketAddresses packet_addresses(const uint8_t* packet_data, uint32_t packet_length)
{
	ParsedPacket parsed;
	if (!parse_packet(packet_data, packet_length, parsed))
		return {};

	if (parsed.ipv4 != nullptr)
		return {format_ipv4_address(parsed.ipv4->SrcAddr), format_ipv4_address(parsed.ipv4->DstAddr)};
	if (parsed.ipv6 != nullptr)
		return {format_ipv6_address(parsed.ipv6->SrcAddr), format_ipv6_address(parsed.ipv6->DstAddr)};
	return {};
}

std::string endpoint_address(const ParsedPacket& parsed, bool destination)
{
	if (parsed.ipv4)
		return format_ipv4_address(destination ? parsed.ipv4->DstAddr : parsed.ipv4->SrcAddr);
	if (parsed.ipv6)
		return format_ipv6_address(destination ? parsed.ipv6->DstAddr : parsed.ipv6->SrcAddr);
	return {};
}
