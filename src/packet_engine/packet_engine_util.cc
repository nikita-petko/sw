#include "packet_engine_util.h"

#include <algorithm>
#include <cstdio>
#include <string>

#include "log.h"

std::string format_win32_error(DWORD error)
{
	char*		message = nullptr;
	const DWORD length	= FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
										 nullptr,
										 error,
										 0,
										 reinterpret_cast<char*>(&message),
										 0,
										 nullptr);
	if (length == 0)
		return "unknown error";
	std::string result(message, length);
	LocalFree(message);
	while (!result.empty() && (result.back() == '\r' || result.back() == '\n'))
		result.pop_back();
	return result;
}

bool pcap_files_enabled_for(const PcapFilesOptions& pcap_files, const ProfileOptions& profile)
{
	return pcap_files.enabled &&
		   std::any_of(pcap_files.enabled_for.begin(), pcap_files.enabled_for.end(), [&](const std::string& enabled_profile) {
			   return enabled_profile == "*" || enabled_profile == profile.name;
		   });
}

std::string format_guid(const GUID& guid)
{
	char text[37] = {};
	std::snprintf(text,
				  sizeof(text),
				  "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				  static_cast<unsigned long>(guid.Data1),
				  guid.Data2,
				  guid.Data3,
				  guid.Data4[0],
				  guid.Data4[1],
				  guid.Data4[2],
				  guid.Data4[3],
				  guid.Data4[4],
				  guid.Data4[5],
				  guid.Data4[6],
				  guid.Data4[7]);
	return text;
}

void write_pcap_u32(std::ofstream& file, uint32_t value)
{
	file.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

void write_pcap_u16(std::ofstream& file, uint16_t value)
{
	file.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

const char* key_name(int key)
{
	if (key == 0x20)
		return "space";
	if (key == 0x12)
		return "alt";
	if (key == 0x11)
		return "ctrl";
	if (key == 0x10)
		return "shift";
	return nullptr;
}

std::string format_keys(const ProfileOptions& profile)
{
	std::string result;
	const char* separator = profile.key_mode == ProfileKeyMode::oneof ? " or " : "+";
	for (const int key : profile.keys)
	{
		if (!result.empty())
			result += separator;
		if (const char* name = key_name(key))
			result += name;
		else if (key >= 0x20 && key <= 0x7E)
			result += static_cast<char>(key);
		else
			result += std::to_string(key);
	}
	return result;
}

std::string format_state_divider(size_t width, const std::string& label)
{
	const size_t inner_width = width - 2;
	if (label.empty())
		return "|" + std::string(inner_width, '-') + "|";

	const std::string text		 = " " + label + " ";
	const size_t	  left_width = (inner_width - text.size()) / 2;
	return "|" + std::string(left_width, '-') + text + std::string(inner_width - left_width - text.size(), '-') + "|";
}

std::string format_tcp_flags(const WINDIVERT_TCPHDR& tcp_header)
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

std::string format_ipv4_address(UINT32 address)
{
	const auto* bytes	   = reinterpret_cast<const unsigned char*>(&address);
	char		buffer[16] = {};
	std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
	return buffer;
}

std::string format_ipv6_address(const UINT32* address)
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

PacketAddresses packet_addresses(const BYTE* packet_data, UINT packet_length)
{
	PWINDIVERT_IPHDR   ip_header   = nullptr;
	PWINDIVERT_IPV6HDR ipv6_header = nullptr;
	if (!WinDivertHelperParsePacket(packet_data,
									packet_length,
									&ip_header,
									&ipv6_header,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr))
		return {};

	if (ip_header != nullptr)
		return {format_ipv4_address(ip_header->SrcAddr), format_ipv4_address(ip_header->DstAddr)};
	if (ipv6_header != nullptr)
		return {format_ipv6_address(ipv6_header->SrcAddr), format_ipv6_address(ipv6_header->DstAddr)};
	return {};
}
