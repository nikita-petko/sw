#include "packet_mode.h"

#include <algorithm>
#include <limits>

namespace {
class RatioMode final : public PacketMode
{
public:
	explicit RatioMode(ProfileOptions options) : PacketMode(std::move(options), "ratio") {}

	void capture_packet(const BYTE*				 packet,
						UINT					 length,
						const WINDIVERT_ADDRESS& address,
						int						 profile,
						uint64_t				 now,
						uint64_t				 receive_order,
						PacketQueue&			 packets) override
	{
		if (packets.empty())
		{
			ratio_release_at_	 = now + static_cast<uint64_t>(options_.delay_ms);
			ratio_batch_packets_ = 0;
		}
		else if (!options_.ratio_percent && ratio_batch_packets_ >= options_.ratio)
		{
			ratio_release_at_ += static_cast<uint64_t>(options_.delay_ms);
			ratio_batch_packets_ = 0;
		}
		packets.push(make_packet_node(packet, length, address, profile, ratio_release_at_, receive_order));
		if (!options_.ratio_percent)
			++ratio_batch_packets_;
	}

	void release(PacketQueue& packets, uint64_t now, std::vector<PacketNode*>& ready_packets) override
	{
		if (!options_.ratio_percent)
		{
			collect_due_packets(packets, now, ready_packets);
			return;
		}

		std::vector<PacketNode*> queued_packets;
		while (!packets.empty())
		{
			PacketNode* node = packets.top();
			packets.pop();
			if (node == nullptr || node->address == nullptr)
				destroy_packet_node(node);
			else
				queued_packets.push_back(node);
		}
		const size_t send_count = (std::max<size_t>)(1, (queued_packets.size() * static_cast<size_t>(options_.ratio) + 99) / 100);
		ratio_release_at_		= now + static_cast<uint64_t>(options_.delay_ms);
		for (size_t index = 0; index < queued_packets.size(); ++index)
		{
			PacketNode* node = queued_packets[index];
			if (index < send_count)
				ready_packets.push_back(node);
			else
			{
				node->release_at = ratio_release_at_;
				packets.push(node);
			}
		}
	}

	void flush(PacketQueue& packets, std::vector<PacketNode*>& pending_packets) override
	{
		while (!packets.empty())
		{
			pending_packets.push_back(packets.top());
			packets.pop();
		}
	}

private:
	uint64_t ratio_release_at_	  = 0;
	int32_t	 ratio_batch_packets_ = 0;
};
}  // namespace

std::unique_ptr<PacketMode> create_ratio_mode(const ProfileOptions& options)
{
	return std::make_unique<RatioMode>(options);
}
