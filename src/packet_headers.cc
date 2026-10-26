#include "packet_headers.h"

#include <cstring>

namespace {
constexpr uint8_t kProtocolTcp = 6;
constexpr uint8_t kProtocolUdp = 17;

void locate_transport(uint8_t* base, uint32_t offset, uint32_t end, uint8_t protocol, bool fragmented, ParsedPacket& parsed)
{
	if (fragmented || offset > end)
		return;
	const uint32_t available = end - offset;
	if (protocol == kProtocolTcp && available >= sizeof(TcpHeader))
	{
		auto* tcp = reinterpret_cast<TcpHeader*>(base + offset);
		if (tcp->HdrLength >= 5 && static_cast<uint32_t>(tcp->HdrLength) * 4 <= available)
			parsed.tcp = tcp;
	}
	else if (protocol == kProtocolUdp && available >= sizeof(UdpHeader))
		parsed.udp = reinterpret_cast<UdpHeader*>(base + offset);
}

bool parse_ipv4(uint8_t* packet, uint32_t length, ParsedPacket& parsed)
{
	if (length < sizeof(Ipv4Header))
		return false;
	auto*		   header		 = reinterpret_cast<Ipv4Header*>(packet);
	const uint32_t header_length = static_cast<uint32_t>(header->HdrLength) * 4;
	const uint32_t total_length	 = static_cast<uint32_t>(((header->Length & 0xFF) << 8) | (header->Length >> 8));
	if (header->HdrLength < 5 || header_length > length || total_length < header_length || total_length > length)
		return false;
	parsed.ipv4 = header;
	// bits other than the DF/MF flags hold the fragment offset (network byte order)
	const bool fragmented = (header->FragOff0 & 0xFF1F) != 0;
	locate_transport(packet, header_length, total_length, header->Protocol, fragmented, parsed);
	return true;
}

bool parse_ipv6(uint8_t* packet, uint32_t length, ParsedPacket& parsed)
{
	if (length < sizeof(Ipv6Header))
		return false;
	auto*		   header	 = reinterpret_cast<Ipv6Header*>(packet);
	const uint32_t payload	 = static_cast<uint32_t>(((header->Length & 0xFF) << 8) | (header->Length >> 8));
	const uint32_t total	 = static_cast<uint32_t>(sizeof(Ipv6Header)) + payload;
	if (total > length)
		return false;
	parsed.ipv6			= header;
	uint8_t	 next		= header->NextHdr;
	uint32_t offset		= sizeof(Ipv6Header);
	bool	 fragmented = false;
	for (;;)
	{
		uint32_t extension_length = 0;
		switch (next)
		{
			case 0:	 // hop-by-hop options
			case 43: // routing
			case 60: // destination options
				if (offset + 2 > total)
					return true;
				extension_length = (static_cast<uint32_t>(packet[offset + 1]) + 1) * 8;
				break;
			case 44: // fragment
				if (offset + 8 > total)
					return true;
				// 13-bit fragment offset spans byte 2 and the top 5 bits of byte 3
				if (packet[offset + 2] != 0 || (packet[offset + 3] & 0xF8) != 0)
					fragmented = true;
				extension_length = 8;
				break;
			case 51: // authentication header
				if (offset + 2 > total)
					return true;
				extension_length = (static_cast<uint32_t>(packet[offset + 1]) + 2) * 4;
				break;
			default:
				locate_transport(packet, offset, total, next, fragmented, parsed);
				return true;
		}
		if (offset + extension_length > total)
			return true;
		next = packet[offset];
		offset += extension_length;
	}
}
}  // namespace

bool parse_packet(uint8_t* packet, uint32_t length, ParsedPacket& parsed)
{
	parsed = {};
	if (packet == nullptr || length == 0)
		return false;
	switch (packet[0] >> 4)
	{
		case 4:
			return parse_ipv4(packet, length, parsed);
		case 6:
			return parse_ipv6(packet, length, parsed);
		default:
			return false;
	}
}

bool parse_packet(const uint8_t* packet, uint32_t length, ParsedPacket& parsed)
{
	return parse_packet(const_cast<uint8_t*>(packet), length, parsed);
}
