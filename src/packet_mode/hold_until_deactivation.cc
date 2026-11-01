#include "packet_mode.h"

#include <algorithm>
#include <limits>
#include <utility>
#include <vector>

namespace {
class HoldUntilDeactivationMode final : public PacketMode
{
public:
	explicit HoldUntilDeactivationMode(ProfileOptions options) : PacketMode(std::move(options), "hold_until_deactivation") {}

	void capture_packet(const uint8_t* packet,
						uint32_t length,
						const backend::PacketMeta& address,
						int profile,
						uint64_t,
						uint64_t receive_order,
						PacketQueue& packets) override
	{
		packets.push(make_packet_node(packet,
									  length,
									  address,
									  profile,
									  (std::numeric_limits<uint64_t>::max)(),
									  receive_order));
	}

	void release(PacketQueue& packets, uint64_t now, std::vector<PacketNode*>& ready_packets) override
	{
		collect_due_packets(packets, now, ready_packets);
	}

	void release_amount(PacketQueue& packets)
	{
		const size_t amount = options_.amount == 0 ? packets.size() : static_cast<size_t>(options_.amount);
		std::vector<PacketNode*> released;
		released.reserve((std::min)(amount, packets.size()));
		for (size_t index = 0; index < amount && !packets.empty(); ++index)
		{
			PacketNode* node = packets.top();
			packets.pop();
			released.push_back(node);
		}
		for (PacketNode* node : released)
		{
			node->release_at = 0;
			packets.push(node);
		}
	}

	bool toggle(PacketQueue& packets) override
	{
		release_amount(packets);
		return true;
	}

	void flush_on_demand(PacketQueue& packets) override
	{
		release_amount(packets);
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

std::unique_ptr<PacketMode> create_hold_until_deactivation_mode(const ProfileOptions& options)
{
	return std::make_unique<HoldUntilDeactivationMode>(options);
}