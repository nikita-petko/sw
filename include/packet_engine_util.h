#ifndef PACKET_ENGINE_UTIL_H_
#define PACKET_ENGINE_UTIL_H_

#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include "packet_engine.h"
#include "packet_headers.h"

/// Returns whether PCAP capture is enabled globally and for the given profile.
bool pcap_files_enabled_for(const PcapFilesOptions& pcap_files, const ProfileOptions& profile);
/// Writes a 32-bit value to a PCAP stream in the platform's byte order.
void write_pcap_u32(std::ofstream& file, uint32_t value);
/// Writes a 16-bit value to a PCAP stream in the platform's byte order.
void write_pcap_u16(std::ofstream& file, uint16_t value);

/// The PCAP file one profile session records its captured packets to. `file` is null while no capture is active.
struct PcapCapture
{
	std::unique_ptr<std::ofstream> file;
	std::string					   guid;
	std::string					   path;
};
/// Creates the profile's PCAP file (named after a new GUID) in the configured directory and writes the PCAP header.
/// On failure the reason is logged and `capture.file` stays null.
void start_pcap_capture(const PcapFilesOptions& pcap_files, int profile, const ProfileOptions& profile_options, PcapCapture& capture);
/// Appends a received packet (with a PCAP record header and the current time) to the capture. On a write failure the
/// error is logged under `profile_label` and `capture.file` is reset.
void record_pcap_packet(PcapCapture& capture, const uint8_t* packet_data, uint32_t length, const std::string& profile_label);

/// Creates a state-report divider of the requested width, optionally centered around a label.
std::string format_state_divider(size_t width, const std::string& label = {});
/// Wraps a value in ANSI color codes for emphasis in state-report output.
std::string highlight(const std::string& value);
/// Returns the text length excluding ANSI SGR color sequences.
size_t visible_length(const std::string& text);
/// Logs a state-report line padded to fit the requested width.
void log_state_line(size_t width, const std::string& text);

/// Formats the enabled TCP flags as a comma-separated list, or "-" if none are set.
std::string format_tcp_flags(const TcpHeader& tcp_header);
/// Formats an IPv4 address in dotted-decimal notation.
std::string format_ipv4_address(uint32_t address);
/// Formats an IPv6 address as eight hexadecimal groups.
std::string format_ipv6_address(const uint32_t* address);

/// Textual source and destination addresses extracted from a packet.
/// Both fields are empty when the packet cannot be parsed as IPv4 or IPv6.
struct PacketAddresses
{
	std::string source;
	std::string destination;
};

/// Parses a packet and returns its IPv4 or IPv6 source and destination addresses.
PacketAddresses packet_addresses(const uint8_t* packet_data, uint32_t packet_length);

#endif
