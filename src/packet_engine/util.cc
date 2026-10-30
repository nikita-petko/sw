#include "packet_engine_util.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>

#include "log.h"
#include "platform.h"

bool pcap_files_enabled_for(const PcapFilesOptions& pcap_files, const ProfileOptions& profile)
{
	return pcap_files.enabled &&
		   std::any_of(pcap_files.enabled_for.begin(), pcap_files.enabled_for.end(), [&](const std::string& enabled_profile) {
			   return enabled_profile == "*" || enabled_profile == profile.name;
		   });
}

void write_pcap_u32(std::ofstream& file, uint32_t value)
{
	file.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

void write_pcap_u16(std::ofstream& file, uint16_t value)
{
	file.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

void start_pcap_capture(const PcapFilesOptions& pcap_files, int profile, const ProfileOptions& profile_options, PcapCapture& capture)
{
	const std::string guid = platform::generate_guid();
	if (guid.empty())
	{
		LOG_ERROR("profile #%d - %s PCAP capture: failed to generate a GUID", profile, profile_options.name.c_str());
		return;
	}
	capture.guid = guid;
	std::error_code error;
	std::filesystem::create_directories(pcap_files.output_dir, error);
	if (error)
	{
		LOG_ERROR("profile #%d - %s PCAP capture: failed to create directory %s: %s",
				  profile,
				  profile_options.name.c_str(),
				  pcap_files.output_dir.c_str(),
				  error.message().c_str());
		return;
	}
	capture.path = (std::filesystem::path(pcap_files.output_dir) / (capture.guid + ".pcap")).string();
	capture.file = std::make_unique<std::ofstream>(capture.path, std::ios::binary | std::ios::trunc);
	if (!*capture.file)
	{
		LOG_ERROR("profile #%d - %s PCAP capture: failed to open %s", profile, profile_options.name.c_str(), capture.path.c_str());
		capture.file.reset();
		return;
	}
	std::ofstream& file = *capture.file;
	write_pcap_u32(file, 0xa1b2c3d4);
	write_pcap_u16(file, 2);
	write_pcap_u16(file, 4);
	write_pcap_u32(file, 0);
	write_pcap_u32(file, 0);
	write_pcap_u32(file, 0xFFFF);
	write_pcap_u32(file, 101);
	if (!file)
	{
		LOG_ERROR("profile #%d - %s PCAP capture: failed to write header to %s", profile, profile_options.name.c_str(), capture.path.c_str());
		capture.file.reset();
	}
}

void record_pcap_packet(PcapCapture& capture, const uint8_t* packet_data, uint32_t length, const std::string& profile_label)
{
	std::ofstream& file			= *capture.file;
	const auto	   now			= std::chrono::system_clock::now().time_since_epoch();
	const auto	   seconds		= std::chrono::duration_cast<std::chrono::seconds>(now);
	const auto	   microseconds = std::chrono::duration_cast<std::chrono::microseconds>(now - seconds);
	write_pcap_u32(file, static_cast<uint32_t>(seconds.count()));
	write_pcap_u32(file, static_cast<uint32_t>(microseconds.count()));
	write_pcap_u32(file, length);
	write_pcap_u32(file, length);
	file.write(reinterpret_cast<const char*>(packet_data), length);
	if (!file)
	{
		LOG_ERROR("%s PCAP capture: failed to write %s", profile_label.c_str(), capture.path.c_str());
		capture.file.reset();
	}
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
