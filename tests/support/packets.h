// Builders for raw IP packets. Packets are assembled byte by byte so the tests do not depend on the header structs' bit-field layout.
#ifndef TESTS_SUPPORT_PACKETS_H_
#define TESTS_SUPPORT_PACKETS_H_

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace packets {
using Bytes = std::vector<uint8_t>;

constexpr uint8_t kIcmp = 1;
constexpr uint8_t kTcp	= 6;
constexpr uint8_t kUdp	= 17;

/// TCP flag bits for tcp_segment().
constexpr uint8_t kFin = 0x01;
constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kRst = 0x04;
constexpr uint8_t kPsh = 0x08;
constexpr uint8_t kAck = 0x10;
constexpr uint8_t kUrg = 0x20;

inline void put_u16(Bytes& out, uint16_t value)
{
	out.push_back(static_cast<uint8_t>(value >> 8));
	out.push_back(static_cast<uint8_t>(value & 0xFF));
}

inline void put_u32(Bytes& out, uint32_t value)
{
	put_u16(out, static_cast<uint16_t>(value >> 16));
	put_u16(out, static_cast<uint16_t>(value & 0xFFFF));
}

inline void append(Bytes& out, const Bytes& more)
{
	out.insert(out.end(), more.begin(), more.end());
}

/// `flags` is the TCP flag byte (kFin ... kUrg); `words` the data offset in 32-bit words.
inline Bytes tcp_segment(uint16_t source_port, uint16_t destination_port, uint32_t sequence, uint32_t acknowledgment, uint8_t flags, uint8_t words = 5, size_t payload = 0)
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

inline Bytes udp_datagram(uint16_t source_port, uint16_t destination_port, size_t payload)
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
inline Bytes ipv4_packet(uint8_t protocol, const Bytes& payload, std::array<uint8_t, 4> source = {10, 0, 0, 1}, std::array<uint8_t, 4> destination = {192, 168, 1, 20},
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
/// The source address ends in ::1 and the destination in ::2, both inside 2001::/16.
inline Bytes ipv6_packet(uint8_t next_header, const Bytes& payload, int declared_length = -1)
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

/// A bare IPv4 TCP packet from 10.0.0.1:1000 to 192.168.1.20:2000.
inline Bytes tcp_packet(uint32_t sequence, uint32_t acknowledgment, uint8_t flags = kAck, uint16_t source_port = 1000, uint16_t destination_port = 2000)
{
	return ipv4_packet(kTcp, tcp_segment(source_port, destination_port, sequence, acknowledgment, flags));
}

}  // namespace packets

#endif
