#include "packet_mode.h"

#include <limits>

namespace {
class SendAllAfterDelayMode final : public PacketMode
{
public:
	explicit SendAllAfterDelayMode(ProfileOptions options) : PacketMode(std::move(options), "send_all_after_delay") {}

	void capture_packet(const uint8_t*				 packet,
						uint32_t					 length,
						const backend::PacketMeta& address,
						int						 profile,
						uint64_t				 now,
						uint64_t				 receive_order,
						PacketQueue&			 packets) override
	{
		uint64_t release_at =
			options_.delay_ms <= 0 ? (std::numeric_limits<uint64_t>::max)() : now + static_cast<uint64_t>(options_.delay_ms);
		if (!packets.empty())
			release_at = packets.top()->release_at;
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

std::unique_ptr<PacketMode> create_send_all_after_delay_mode(const ProfileOptions& options)
{
	return std::make_unique<SendAllAfterDelayMode>(options);
}
