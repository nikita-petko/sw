// Unit tests for packet parsing (src/packet_headers.cc) and the packet formatting helpers (src/packet_engine/util.cc).
// Packets are assembled byte by byte so the tests do not depend on the header structs' bit-field layout.
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "packet_engine_util.h"
#include "packet_headers.h"
#include "support/test.h"

namespace {
using Bytes = std::vector<uint8_t>;

constexpr uint8_t kIcmp = 1;
constexpr uint8_t kTcp	= 6;
constexpr uint8_t kUdp	= 17;

void put_u16(Bytes& out, uint16_t value)
{
	out.push_back(static_cast<uint8_t>(value >> 8));
	out.push_back(static_cast<uint8_t>(value & 0xFF));
}

void put_u32(Bytes& out, uint32_t value)
{
	put_u16(out, static_cast<uint16_t>(value >> 16));
	put_u16(out, static_cast<uint16_t>(value & 0xFFFF));
}

void append(Bytes& out, const Bytes& more)
{
	out.insert(out.end(), more.begin(), more.end());
}

/// `flags` is the TCP flag byte (FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 URG=0x20); `words` the data offset.
Bytes tcp_segment(uint16_t source_port, uint16_t destination_port, uint32_t sequence, uint32_t acknowledgment, uint8_t flags, uint8_t words = 5, size_t payload = 0)
{
	Bytes out;
	put_u16(out, source_port);
	put_u16(out, destination_port);
	put_u32(out, sequence);
	put_u32(out, acknowledgment);
	out.push_back(static_cast<uint8_t>(words << 4));
	out.push_back(flags);
	put_u16(out, 8192);
	put_u16(out, 0);
	put_u16(out, 0);
	out.resize((std::max)(static_cast<size_t>(words) * 4, out.size()), 0);
	out.resize(out.size() + payload, 0xAB);
	return out;
}

Bytes udp_datagram(uint16_t source_port, uint16_t destination_port, size_t payload)
{
	Bytes out;
	put_u16(out, source_port);
	put_u16(out, destination_port);
	put_u16(out, static_cast<uint16_t>(8 + payload));
	put_u16(out, 0);
	out.resize(out.size() + payload, 0xCD);
	return out;
}

/// `fragment_field` is the raw flags + fragment-offset word (DF = 0x4000, MF = 0x2000); `words` the header length in 32-bit words.
Bytes ipv4_packet(uint8_t protocol, const Bytes& payload, std::array<uint8_t, 4> source = {10, 0, 0, 1}, std::array<uint8_t, 4> destination = {192, 168, 1, 20},
				  uint16_t fragment_field = 0, uint8_t words = 5)
{
	Bytes out;
	out.push_back(static_cast<uint8_t>(0x40 | words));
	out.push_back(0);
	put_u16(out, static_cast<uint16_t>(words * 4 + payload.size()));
	put_u16(out, 0x1234);
	put_u16(out, fragment_field);
	out.push_back(64);
	out.push_back(protocol);
	put_u16(out, 0);
	out.insert(out.end(), source.begin(), source.end());
	out.insert(out.end(), destination.begin(), destination.end());
	out.resize(static_cast<size_t>(words) * 4, 0);
	append(out, payload);
	return out;
}

/// An IPv6 packet whose payload length field is `payload.size()` unless `declared_length` says otherwise.
Bytes ipv6_packet(uint8_t next_header, const Bytes& payload, int declared_length = -1)
{
	Bytes out;
	out.push_back(0x60);
	out.insert(out.end(), {0, 0, 0});
	put_u16(out, static_cast<uint16_t>(declared_length >= 0 ? declared_length : static_cast<int>(payload.size())));
	out.push_back(next_header);
	out.push_back(64);
	for (uint8_t index = 0; index < 16; ++index)
		out.push_back(static_cast<uint8_t>(index == 15 ? 1 : (index == 0 ? 0x20 : (index == 1 ? 0x01 : 0))));
	for (uint8_t index = 0; index < 16; ++index)
		out.push_back(static_cast<uint8_t>(index == 15 ? 2 : (index == 0 ? 0x20 : (index == 1 ? 0x01 : 0))));
	append(out, payload);
	return out;
}

bool parse(Bytes& packet, ParsedPacket& parsed)
{
	return parse_packet(packet.data(), static_cast<uint32_t>(packet.size()), parsed);
}

void test_ipv4_tcp()
{
	Bytes		 packet = ipv4_packet(kTcp, tcp_segment(51000, 443, 0x01020304, 0x0A0B0C0D, 0x12));
	ParsedPacket parsed;
	CHECK(parse(packet, parsed));
	CHECK(parsed.ipv4 != nullptr && parsed.ipv6 == nullptr && parsed.tcp != nullptr && parsed.udp == nullptr);
	CHECK(parsed.ipv4->Protocol == kTcp && parsed.ipv4->TTL == 64);
	CHECK(swap_u16(parsed.tcp->SrcPort) == 51000 && swap_u16(parsed.tcp->DstPort) == 443);
	CHECK(swap_u32(parsed.tcp->SeqNum) == 0x01020304u && swap_u32(parsed.tcp->AckNum) == 0x0A0B0C0Du);
	CHECK(parsed.tcp->Syn == 1 && parsed.tcp->Ack == 1 && parsed.tcp->Fin == 0 && parsed.tcp->Rst == 0);
	CHECK(format_tcp_flags(*parsed.tcp) == "SYN,ACK");
}

void test_ipv4_udp()
{
	Bytes		 packet = ipv4_packet(kUdp, udp_datagram(5353, 55001, 12));
	ParsedPacket parsed;
	CHECK(parse(packet, parsed));
	CHECK(parsed.ipv4 != nullptr && parsed.tcp == nullptr && parsed.udp != nullptr);
	CHECK(swap_u16(parsed.udp->SrcPort) == 5353 && swap_u16(parsed.udp->DstPort) == 55001);
}

void test_parsed_pointers_alias_the_buffer()
{
	Bytes		 packet = ipv4_packet(kTcp, tcp_segment(1, 2, 3, 4, 0x10));
	ParsedPacket parsed;
	CHECK(parse(packet, parsed));
	CHECK(reinterpret_cast<uint8_t*>(parsed.ipv4) == packet.data());
	CHECK(reinterpret_cast<uint8_t*>(parsed.tcp) == packet.data() + 20);
	parsed.tcp->AckNum = swap_u32(99);
	CHECK(packet[28] == 0 && packet[31] == 99);

	const Bytes constant = packet;
	ParsedPacket from_const;
	CHECK(parse_packet(constant.data(), static_cast<uint32_t>(constant.size()), from_const));
	CHECK(from_const.tcp != nullptr && swap_u32(from_const.tcp->AckNum) == 99u);
}

void test_ipv4_options_shift_the_transport_header()
{
	Bytes		 packet = ipv4_packet(kUdp, udp_datagram(1000, 2000, 4), {1, 2, 3, 4}, {5, 6, 7, 8}, 0, 7);
	ParsedPacket parsed;
	CHECK(parse(packet, parsed));
	CHECK(parsed.udp != nullptr && reinterpret_cast<uint8_t*>(parsed.udp) == packet.data() + 28);
	CHECK(swap_u16(parsed.udp->DstPort) == 2000);
}

void test_ipv4_without_a_known_transport()
{
	Bytes		 packet = ipv4_packet(kIcmp, Bytes(8, 0));
	ParsedPacket parsed;
	CHECK(parse(packet, parsed));
	CHECK(parsed.ipv4 != nullptr && parsed.tcp == nullptr && parsed.udp == nullptr);
}

void test_ipv4_fragments_have_no_transport()
{
	const Bytes segment = tcp_segment(1, 2, 3, 4, 0x10);
	ParsedPacket parsed;

	Bytes dont_fragment = ipv4_packet(kTcp, segment, {1, 1, 1, 1}, {2, 2, 2, 2}, 0x4000);
	CHECK(parse(dont_fragment, parsed) && parsed.tcp != nullptr);

	// A first fragment (offset 0, more-fragments set) still carries the transport header, as in IPv6.
	Bytes more_fragments = ipv4_packet(kTcp, segment, {1, 1, 1, 1}, {2, 2, 2, 2}, 0x2000);
	CHECK(parse(more_fragments, parsed) && parsed.tcp != nullptr);

	Bytes later_fragment = ipv4_packet(kTcp, segment, {1, 1, 1, 1}, {2, 2, 2, 2}, 0x0010);
	CHECK(parse(later_fragment, parsed) && parsed.ipv4 != nullptr && parsed.tcp == nullptr);

	// A high offset bit with the DF flag set is still a fragment.
	Bytes high_offset = ipv4_packet(kTcp, segment, {1, 1, 1, 1}, {2, 2, 2, 2}, 0x4100);
	CHECK(parse(high_offset, parsed) && parsed.ipv4 != nullptr && parsed.tcp == nullptr);
}

void test_ipv4_trailing_bytes_are_ignored()
{
	Bytes packet = ipv4_packet(kTcp, tcp_segment(1, 2, 3, 4, 0x10));
	packet.resize(packet.size() + 6, 0xEE);
	ParsedPacket parsed;
	CHECK(parse(packet, parsed) && parsed.tcp != nullptr);
}

void test_malformed_ipv4_is_rejected()
{
	ParsedPacket parsed;
	CHECK(!parse_packet(static_cast<const uint8_t*>(nullptr), 40, parsed));
	const Bytes valid = ipv4_packet(kTcp, tcp_segment(1, 2, 3, 4, 0x10));
	CHECK(!parse_packet(valid.data(), 0, parsed));

	for (uint32_t length = 1; length < sizeof(Ipv4Header); ++length)
		CHECK(!parse_packet(valid.data(), length, parsed));

	// A packet cut short is shorter than its own total-length field.
	for (uint32_t length = sizeof(Ipv4Header); length < valid.size(); ++length)
	{
		const bool ok = parse_packet(valid.data(), length, parsed);
		CHECK(!ok);
		CHECK(parsed.ipv4 == nullptr && parsed.tcp == nullptr);
	}

	Bytes version5 = valid;
	version5[0]	   = 0x55;
	CHECK(!parse(version5, parsed));

	Bytes header_words_too_small = valid;
	header_words_too_small[0]	= 0x44;
	CHECK(!parse(header_words_too_small, parsed));

	Bytes header_longer_than_packet = valid;
	header_longer_than_packet[0]	= 0x4F;
	header_longer_than_packet.resize(40);
	CHECK(!parse(header_longer_than_packet, parsed));

	Bytes total_shorter_than_header = valid;
	total_shorter_than_header[2]	= 0;
	total_shorter_than_header[3]	= 12;
	CHECK(!parse(total_shorter_than_header, parsed));
}

void test_failed_parse_resets_the_result()
{
	Bytes		 good = ipv4_packet(kTcp, tcp_segment(1, 2, 3, 4, 0x10));
	ParsedPacket parsed;
	CHECK(parse(good, parsed) && parsed.tcp != nullptr);
	Bytes bad = {0x00};
	CHECK(!parse(bad, parsed));
	CHECK(parsed.ipv4 == nullptr && parsed.ipv6 == nullptr && parsed.tcp == nullptr && parsed.udp == nullptr);
}

void test_truncated_or_invalid_tcp_header()
{
	ParsedPacket parsed;

	// Fewer bytes than a minimal TCP header.
	Bytes short_segment = ipv4_packet(kTcp, Bytes(12, 0));
	CHECK(parse(short_segment, parsed) && parsed.ipv4 != nullptr && parsed.tcp == nullptr);

	// A data offset below 5 words is invalid.
	Bytes small_offset = ipv4_packet(kTcp, tcp_segment(1, 2, 3, 4, 0x10, 4));
	small_offset[20 + 12] = 0x40;
	CHECK(parse(small_offset, parsed) && parsed.tcp == nullptr);

	// A data offset that reaches past the end of the packet.
	Bytes large_offset = ipv4_packet(kTcp, tcp_segment(1, 2, 3, 4, 0x10));
	large_offset[20 + 12] = 0xF0;
	CHECK(parse(large_offset, parsed) && parsed.tcp == nullptr);

	// Options that fit are accepted.
	Bytes with_options = ipv4_packet(kTcp, tcp_segment(1, 2, 3, 4, 0x10, 8));
	CHECK(parse(with_options, parsed) && parsed.tcp != nullptr);

	Bytes short_udp = ipv4_packet(kUdp, Bytes(7, 0));
	CHECK(parse(short_udp, parsed) && parsed.ipv4 != nullptr && parsed.udp == nullptr);
}

void test_ipv6_transport()
{
	ParsedPacket parsed;
	Bytes		 tcp = ipv6_packet(kTcp, tcp_segment(40000, 8080, 7, 8, 0x02));
	CHECK(parse(tcp, parsed));
	CHECK(parsed.ipv6 != nullptr && parsed.ipv4 == nullptr && parsed.tcp != nullptr);
	CHECK(swap_u16(parsed.tcp->DstPort) == 8080 && format_tcp_flags(*parsed.tcp) == "SYN");

	Bytes udp = ipv6_packet(kUdp, udp_datagram(1, 2, 3));
	CHECK(parse(udp, parsed) && parsed.udp != nullptr && parsed.tcp == nullptr);
}

void test_ipv6_extension_headers()
{
	ParsedPacket parsed;

	// Hop-by-hop options (8 bytes) in front of TCP.
	Bytes hop_by_hop = {kTcp, 0, 0, 0, 0, 0, 0, 0};
	append(hop_by_hop, tcp_segment(1, 2, 3, 4, 0x10));
	Bytes packet = ipv6_packet(0, hop_by_hop);
	CHECK(parse(packet, parsed) && parsed.tcp != nullptr);
	CHECK(reinterpret_cast<uint8_t*>(parsed.tcp) == packet.data() + 48);

	// A first fragment (offset 0, more-fragments set) still carries the transport header.
	Bytes first_fragment = {kUdp, 0, 0x00, 0x01, 0, 0, 0, 1};
	append(first_fragment, udp_datagram(1, 2, 4));
	Bytes first = ipv6_packet(44, first_fragment);
	CHECK(parse(first, parsed) && parsed.udp != nullptr);

	// A later fragment does not.
	Bytes later_fragment = {kUdp, 0, 0x00, 0x08, 0, 0, 0, 1};
	append(later_fragment, udp_datagram(1, 2, 4));
	Bytes later = ipv6_packet(44, later_fragment);
	CHECK(parse(later, parsed) && parsed.ipv6 != nullptr && parsed.udp == nullptr);

	// Extension headers that run past the end are tolerated without a transport.
	Bytes truncated_extension = {kTcp, 5, 0, 0, 0, 0, 0, 0};
	Bytes truncated			  = ipv6_packet(0, truncated_extension);
	CHECK(parse(truncated, parsed) && parsed.ipv6 != nullptr && parsed.tcp == nullptr);

	Bytes cut_off = ipv6_packet(43, Bytes(1, kTcp));
	CHECK(parse(cut_off, parsed) && parsed.ipv6 != nullptr && parsed.tcp == nullptr);
}

void test_malformed_ipv6_is_rejected()
{
	ParsedPacket parsed;
	Bytes		 valid = ipv6_packet(kTcp, tcp_segment(1, 2, 3, 4, 0x10));
	for (uint32_t length = 1; length < valid.size(); ++length)
		CHECK(!parse_packet(valid.data(), length, parsed));

	Bytes lying = ipv6_packet(kTcp, tcp_segment(1, 2, 3, 4, 0x10), 4000);
	CHECK(!parse(lying, parsed));
}

void test_packet_addresses()
{
	Bytes		 v4 = ipv4_packet(kTcp, tcp_segment(1, 2, 3, 4, 0x10), {10, 0, 0, 1}, {192, 168, 1, 20});
	PacketAddresses addresses = packet_addresses(v4.data(), static_cast<uint32_t>(v4.size()));
	CHECK(addresses.source == "10.0.0.1" && addresses.destination == "192.168.1.20");

	Bytes v6 = ipv6_packet(kUdp, udp_datagram(1, 2, 0));
	addresses = packet_addresses(v6.data(), static_cast<uint32_t>(v6.size()));
	CHECK(addresses.source == "2001:0000:0000:0000:0000:0000:0000:0001");
	CHECK(addresses.destination == "2001:0000:0000:0000:0000:0000:0000:0002");

	const Bytes garbage = {0x90, 1, 2, 3};
	addresses			= packet_addresses(garbage.data(), static_cast<uint32_t>(garbage.size()));
	CHECK(addresses.source.empty() && addresses.destination.empty());
}

void test_endpoint_address()
{
	ParsedPacket parsed;
	Bytes		 v4 = ipv4_packet(kUdp, udp_datagram(1, 2, 0), {8, 8, 4, 4}, {1, 0, 0, 1});
	CHECK(parse(v4, parsed));
	CHECK(endpoint_address(parsed, false) == "8.8.4.4" && endpoint_address(parsed, true) == "1.0.0.1");

	Bytes v6 = ipv6_packet(kUdp, udp_datagram(1, 2, 0));
	CHECK(parse(v6, parsed));
	CHECK(endpoint_address(parsed, true).back() == '2' && endpoint_address(parsed, false).back() == '1');

	CHECK(endpoint_address(ParsedPacket{}, true).empty());
}

void test_format_tcp_flags()
{
	TcpHeader header{};
	CHECK(format_tcp_flags(header) == "-");
	header.Fin = 1;
	CHECK(format_tcp_flags(header) == "FIN");
	header.Rst = header.Psh = header.Urg = 1;
	CHECK(format_tcp_flags(header) == "FIN,RST,PSH,URG");
	header.Syn = header.Ack = 1;
	CHECK(format_tcp_flags(header) == "FIN,SYN,RST,PSH,ACK,URG");
}

void test_format_addresses()
{
	const uint8_t  loopback[4] = {127, 0, 0, 1};
	uint32_t	   value;
	std::memcpy(&value, loopback, sizeof(value));
	CHECK(format_ipv4_address(value) == "127.0.0.1");

	const uint8_t  limits[4] = {0, 255, 0, 255};
	std::memcpy(&value, limits, sizeof(value));
	CHECK(format_ipv4_address(value) == "0.255.0.255");

	uint32_t v6[4];
	for (int index = 0; index < 16; ++index)
		reinterpret_cast<uint8_t*>(v6)[index] = static_cast<uint8_t>(0x10 * (index / 2) + index);
	CHECK(format_ipv6_address(v6) == "0001:1213:2425:3637:4849:5a5b:6c6d:7e7f");
}

void test_state_divider()
{
	CHECK(format_state_divider(10) == "|--------|");
	CHECK(format_state_divider(12, "ab") == "|--- ab ---|");
	// An odd amount of padding puts the extra dash on the right.
	CHECK(format_state_divider(13, "ab") == "|--- ab ----|");
	CHECK(format_state_divider(9, "abcde") == "| abcde |");
	CHECK(format_state_divider(40, "title").size() == 40);
}

void test_visible_length()
{
	CHECK(visible_length("") == 0);
	CHECK(visible_length("plain") == 5);
	CHECK(visible_length("\033[31mred\033[0m") == 3);
	CHECK(visible_length("a\033[1;97mb\033[32mc") == 3);
	CHECK(visible_length(highlight("12345")) == 5);
	CHECK(visible_length(highlight("")) == 0);
	// An escape that is not a CSI sequence counts as ordinary text; an unterminated one swallows the rest.
	CHECK(visible_length("a\033b") == 3);
	CHECK(visible_length("ab\033[31") == 2);
}
}  // namespace

int main(int argc, char** argv)
{
	static const test::TestCase cases[] = {
		{"ipv4_tcp", test_ipv4_tcp},
		{"ipv4_udp", test_ipv4_udp},
		{"parsed_pointers_alias_the_buffer", test_parsed_pointers_alias_the_buffer},
		{"ipv4_options_shift_the_transport_header", test_ipv4_options_shift_the_transport_header},
		{"ipv4_without_a_known_transport", test_ipv4_without_a_known_transport},
		{"ipv4_fragments_have_no_transport", test_ipv4_fragments_have_no_transport},
		{"ipv4_trailing_bytes_are_ignored", test_ipv4_trailing_bytes_are_ignored},
		{"malformed_ipv4_is_rejected", test_malformed_ipv4_is_rejected},
		{"failed_parse_resets_the_result", test_failed_parse_resets_the_result},
		{"truncated_or_invalid_tcp_header", test_truncated_or_invalid_tcp_header},
		{"ipv6_transport", test_ipv6_transport},
		{"ipv6_extension_headers", test_ipv6_extension_headers},
		{"malformed_ipv6_is_rejected", test_malformed_ipv6_is_rejected},
		{"packet_addresses", test_packet_addresses},
		{"endpoint_address", test_endpoint_address},
		{"format_tcp_flags", test_format_tcp_flags},
		{"format_addresses", test_format_addresses},
		{"state_divider", test_state_divider},
		{"visible_length", test_visible_length},
	};
	return test::run_tests("packet", cases, argc, argv);
}
