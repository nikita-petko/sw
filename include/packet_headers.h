#ifndef PACKET_HEADERS_H_
#define PACKET_HEADERS_H_

#include <cstdint>

#if defined(_MSC_VER)
#	pragma warning(push)
#	pragma warning(disable : 4214)  // bit-field types other than int
#endif

/// IPv4 header. Multi-byte fields are in network byte order.
struct Ipv4Header
{
	uint8_t	 HdrLength : 4;
	uint8_t	 Version : 4;
	uint8_t	 TOS;
	uint16_t Length;
	uint16_t Id;
	uint16_t FragOff0;
	uint8_t	 TTL;
	uint8_t	 Protocol;
	uint16_t Checksum;
	uint32_t SrcAddr;
	uint32_t DstAddr;
};

/// IPv6 header. Multi-byte fields are in network byte order.
struct Ipv6Header
{
	uint8_t	 TrafficClass0 : 4;
	uint8_t	 Version : 4;
	uint8_t	 FlowLabel0 : 4;
	uint8_t	 TrafficClass1 : 4;
	uint16_t FlowLabel1;
	uint16_t Length;
	uint8_t	 NextHdr;
	uint8_t	 HopLimit;
	uint32_t SrcAddr[4];
	uint32_t DstAddr[4];
};

/// TCP header. Multi-byte fields are in network byte order.
struct TcpHeader
{
	uint16_t SrcPort;
	uint16_t DstPort;
	uint32_t SeqNum;
	uint32_t AckNum;
	uint16_t Reserved1 : 4;
	uint16_t HdrLength : 4;
	uint16_t Fin : 1;
	uint16_t Syn : 1;
	uint16_t Rst : 1;
	uint16_t Psh : 1;
	uint16_t Ack : 1;
	uint16_t Urg : 1;
	uint16_t Reserved2 : 2;
	uint16_t Window;
	uint16_t Checksum;
	uint16_t UrgPtr;
};

/// UDP header. Multi-byte fields are in network byte order.
struct UdpHeader
{
	uint16_t SrcPort;
	uint16_t DstPort;
	uint16_t Length;
	uint16_t Checksum;
};

#if defined(_MSC_VER)
#	pragma warning(pop)
#endif

static_assert(sizeof(Ipv4Header) == 20, "unexpected IPv4 header layout");
static_assert(sizeof(Ipv6Header) == 40, "unexpected IPv6 header layout");
static_assert(sizeof(TcpHeader) == 20, "unexpected TCP header layout");
static_assert(sizeof(UdpHeader) == 8, "unexpected UDP header layout");

/// Pointers into a packet buffer; unset members were not present or not parseable.
struct ParsedPacket
{
	Ipv4Header* ipv4 = nullptr;
	Ipv6Header* ipv6 = nullptr;
	TcpHeader*	tcp	 = nullptr;
	UdpHeader*	udp	 = nullptr;
};

/// Locates the IP and transport headers of a raw IP packet. Returns false when no valid IP header is found.
/// The returned pointers alias `packet`.
bool parse_packet(uint8_t* packet, uint32_t length, ParsedPacket& parsed);
/// Const overload; callers must not modify the returned headers.
bool parse_packet(const uint8_t* packet, uint32_t length, ParsedPacket& parsed);

/// Converts a 32-bit value between network and host byte order (all supported targets are little-endian).
inline uint32_t swap_u32(uint32_t value)
{
	return ((value & 0x000000FFu) << 24) | ((value & 0x0000FF00u) << 8) | ((value & 0x00FF0000u) >> 8) | ((value & 0xFF000000u) >> 24);
}

#endif
