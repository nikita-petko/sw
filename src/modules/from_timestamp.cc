#include "packet_mode.h"

#include <limits>

namespace {
class FromTimestampMode final : public PacketMode
{
public:
	explicit FromTimestampMode(ProfileOptions options) : PacketMode(std::move(options), "from_timestamp") {}

	void capture_packet(const BYTE*			  packet,
				 UINT					  length,
				 const WINDIVERT_ADDRESS& address,
				 int					  profile,
				 uint64_t				  now,
				 uint64_t				  receive_order,
				 PacketQueue&			  packets) override
	{
		const uint64_t release_at =
			options_.delay_ms <= 0 ? (std::numeric_limits<uint64_t>::max)() : now + static_cast<uint64_t>(options_.delay_ms);
		packets.push(make_packet_node(packet, length, address, profile, release_at, receive_order));
	}

	void release(PacketQueue& packets, uint64_t now, std::vector<PacketNode*>& ready_packets) override
	{
		collect_due_packets(packets, now, ready_packets);
	}

	void flush(PacketQueue& packets, std::vector<PacketNode*>& pending_packets) override
	{
		while (!packets.empty())
		{
			pending_packets.push_back(packets.top());
			packets.pop();
		}
	}
};
}  // namespace

std::unique_ptr<PacketMode> create_from_timestamp_mode(const ProfileOptions& options)
{
	return std::make_unique<FromTimestampMode>(options);
}
