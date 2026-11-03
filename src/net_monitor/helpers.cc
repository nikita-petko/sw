// Packet parsing and statistics helpers of the net monitor.
#include "net_monitor.h"

#ifdef LAGSW_FEATURE_NET_MONITOR

#	include <algorithm>

#	include "internal.h"
#	include "packet_headers.h"

namespace net_monitor_detail {

bool seq_gt(uint32_t a, uint32_t b)
{
	return static_cast<int32_t>(a - b) > 0;
}

double elapsed_ms(Clock::time_point from, Clock::time_point to)
{
	return std::chrono::duration<double, std::milli>(to - from).count();
}

uint32_t payload_length(const ParsedPacket& parsed, uint32_t captured_length)
{
	uint32_t ip_header = 0;
	uint32_t total	   = 0;
	if (parsed.ipv4)
	{
		total	  = swap_u16(parsed.ipv4->Length);
		ip_header = static_cast<uint32_t>(parsed.ipv4->HdrLength) * 4;
	}
	else if (parsed.ipv6)
	{
		total	  = static_cast<uint32_t>(swap_u16(parsed.ipv6->Length)) + 40;
		ip_header = 40;
	}
	else
		return 0;
	// Large send offload leaves the length field zero; fall back to the captured size.
	if (total <= ip_header)
		total = captured_length;
	uint32_t header_bytes = ip_header;
	if (parsed.tcp)
		header_bytes += static_cast<uint32_t>(parsed.tcp->HdrLength) * 4;
	else if (parsed.udp)
		header_bytes += 8;
	else
		return 0;
	return total > header_bytes ? total - header_bytes : 0;
}

const char* service_name(uint16_t port)
{
	switch (port)
	{
		case 53:
			return "dns";
		case 80:
			return "http";
		case 443:
			return "https/quic";
		case 3074:
			return "xbox live";
		case 3478:
			return "stun";
		case 3479:
			return "turn";
		case 3480:
			return "turn";
		case 3544:
			return "teredo";
		case 4380:
			return "steam";
		case 5222:
			return "xmpp";
		case 9308:
			return "playstation";
		case 27015:
			return "source";
		default:
			return "";
	}
}

size_t rtt_bucket(double rtt_ms)
{
	size_t bucket = 0;
	while (bucket < 5 && rtt_ms >= kRttLimits[bucket])
		++bucket;
	return bucket;
}

size_t size_bucket(uint32_t length)
{
	size_t bucket = 0;
	while (bucket < 3 && length >= kSizeLimits[bucket])
		++bucket;
	return bucket;
}

double percentile(std::vector<double> samples, double fraction)
{
	if (samples.empty())
		return 0;
	std::sort(samples.begin(), samples.end());
	return samples[std::min(samples.size() - 1, static_cast<size_t>(fraction * static_cast<double>(samples.size())))];
}

double last_value(const std::deque<double>& values)
{
	return values.empty() ? 0.0 : values.back();
}

int initial_ttl(int observed)
{
	for (const int initial : {32, 64, 128, 255})
		if (observed <= initial)
			return initial;
	return 255;
}

double stability_score(double retransmit_percent, double jitter_ms, double arrival_jitter_ms, uint64_t resets, uint64_t stalls)
{
	const double penalty = std::min(40.0, retransmit_percent * 8) + std::min(25.0, jitter_ms / 2) + std::min(15.0, arrival_jitter_ms / 5) +
						   std::min(10.0, static_cast<double>(resets) * 2) + std::min(10.0, static_cast<double>(stalls));
	return std::max(0.0, 100.0 - penalty);
}

}  // namespace net_monitor_detail

#endif	// LAGSW_FEATURE_NET_MONITOR
