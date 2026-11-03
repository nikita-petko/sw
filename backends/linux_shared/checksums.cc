// backend::calc_checksums for the Linux backends (NFQUEUE and swdivert): the engine recomputes the checksums of a packet it modified
// before sending it back, and both backends hand the bytes to the kernel as they are.
#include <cstdint>

#include "packet_backend.h"

namespace backend {
namespace {
	constexpr uint32_t kMinIpv4Header = 20;
}  // namespace

void calc_checksums(uint8_t* packet, uint32_t length)
{
	if (length < kMinIpv4Header || (packet[0] >> 4) != 4)
		return;
	const uint32_t ip_length = (packet[0] & 0x0F) * 4u;
	if (ip_length < kMinIpv4Header || ip_length > length)
		return;

	auto sum16 = [](const uint8_t* data, uint32_t size, uint32_t initial) {
		uint32_t sum = initial;
		for (; size > 1; size -= 2, data += 2)
			sum += static_cast<uint32_t>(data[0]) << 8 | data[1];
		if (size == 1)
			sum += static_cast<uint32_t>(data[0]) << 8;
		while (sum >> 16)
			sum = (sum & 0xFFFF) + (sum >> 16);
		return sum;
	};

	packet[10] = packet[11] = 0;
	const uint16_t ip_sum	= static_cast<uint16_t>(~sum16(packet, ip_length, 0));
	packet[10]				= ip_sum >> 8;
	packet[11]				= ip_sum & 0xFF;

	const uint8_t  protocol		= packet[9];
	const uint32_t total_length = (static_cast<uint32_t>(packet[2]) << 8 | packet[3]);
	const uint32_t end			= total_length != 0 && total_length <= length ? total_length : length;
	if (end <= ip_length)
		return;
	const uint32_t segment_length = end - ip_length;
	uint32_t	   checksum_offset;
	if (protocol == 6)
		checksum_offset = 16;
	else if (protocol == 17)
		checksum_offset = 6;
	else
		return;
	if (segment_length < checksum_offset + 2)
		return;
	uint8_t* segment		 = packet + ip_length;
	segment[checksum_offset] = segment[checksum_offset + 1] = 0;
	uint32_t sum											= sum16(packet + 12, 8, 0) + protocol + segment_length;
	sum														= sum16(segment, segment_length, sum);
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	uint16_t result = static_cast<uint16_t>(~sum);
	// A computed UDP checksum of zero is transmitted as all ones.
	if (protocol == 17 && result == 0)
		result = 0xFFFF;
	segment[checksum_offset]	 = result >> 8;
	segment[checksum_offset + 1] = result & 0xFF;
}
}  // namespace backend
