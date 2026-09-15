#include "packet_mode.h"

#include <algorithm>
#include <limits>
#include <utility>
#include <vector>

namespace {
class HoldAndSendMode final : public PacketMode
{
public:
	explicit HoldAndSendMode(ProfileOptions options) : PacketMode(std::move(options), "hold_and_send") {}

	void reset() override
	{
		PacketMode::reset();
		held_packets_ = 0;
		held_packet_numbers_.clear();
	}

	void capture_packet(const BYTE*                 packet,
						UINT                         length,
						const WINDIVERT_ADDRESS&     address,
						int                          profile,
						uint64_t                    now,
						uint64_t                    receive_order,
						PacketQueue&                 packets) override
	{
		uint32_t sequence = 0;
		uint32_t acknowledgment = 0;
		const bool has_tcp_numbers = get_tcp_numbers(packet, length, sequence, acknowledgment);
		const bool hold_subsequent = has_tcp_numbers && std::any_of(held_packet_numbers_.begin(), held_packet_numbers_.end(), [&](const auto& held) {
			switch (options_.subsequent_packet_hold_mode)
			{
				case SubsequentPacketHoldMode::seq_only:
					return sequence == held.first;
				case SubsequentPacketHoldMode::ack_only:
					return acknowledgment == held.second;
				case SubsequentPacketHoldMode::seq_ack:
					return sequence == held.first && acknowledgment == held.second;
				case SubsequentPacketHoldMode::none:
				default:
					return false;
			}
		});
		const bool hold = hold_subsequent || held_packets_ < static_cast<size_t>(options_.ratio);
		if (hold)
		{
			if (!hold_subsequent)
				++held_packets_;
			if (has_tcp_numbers && !hold_subsequent)
				held_packet_numbers_.emplace_back(sequence, acknowledgment);
		}
		packets.push(make_packet_node(packet,
									  length,
									  address,
									  profile,
									  hold ? (std::numeric_limits<uint64_t>::max)() : now,
									  receive_order));
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

private:
	size_t held_packets_ = 0;
	std::vector<std::pair<uint32_t, uint32_t>> held_packet_numbers_;
};
}  // namespace

std::unique_ptr<PacketMode> create_hold_and_send_mode(const ProfileOptions& options)
{
	return std::make_unique<HoldAndSendMode>(options);
}