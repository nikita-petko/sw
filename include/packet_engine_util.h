#ifndef PACKET_ENGINE_UTIL_H_
#define PACKET_ENGINE_UTIL_H_

#include <windows.h>
#include <cstdint>
#include <fstream>
#include <string>
#include "packet_engine.h"
#include "windivert_runtime.h"

std::string format_win32_error(DWORD error);

bool pcap_files_enabled_for(const PcapFilesOptions& pcap_files, const ProfileOptions& profile);
std::string format_guid(const GUID& guid);
void write_pcap_u32(std::ofstream& file, uint32_t value);
void write_pcap_u16(std::ofstream& file, uint16_t value);

const char* key_name(int key);
std::string format_keys(const ProfileOptions& profile);

std::string format_state_divider(size_t width, const std::string& label = {});
std::string highlight(const std::string& value);
size_t visible_length(const std::string& text);
void log_state_line(size_t width, const std::string& text);

std::string format_tcp_flags(const WINDIVERT_TCPHDR& tcp_header);
std::string format_ipv4_address(UINT32 address);
std::string format_ipv6_address(const UINT32* address);

struct PacketAddresses
{
	std::string source;
	std::string destination;
};

PacketAddresses packet_addresses(const BYTE* packet_data, UINT packet_length);

#endif
