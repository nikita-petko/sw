#include "packet_mode.h"

#include <limits>

namespace {
class DropUntilToggleMode final : public PacketMode
{
public:
	explicit DropUntilToggleMode(ProfileOptions options) : PacketMode(std::move(options), "drop_until_toggle") {}

	void reset() override
	{
		PacketMode::reset();
		phase_ = Phase::dropping;
	}

	void capture_packet(const BYTE*				 packet,
						UINT					 length,
						const WINDIVERT_ADDRESS& address,
						int						 profile,
						uint64_t,
						uint64_t	 receive_order,
						PacketQueue& packets) override
	{
		if (phase_ != Phase::holding)
			return;
		packets.push(make_packet_node(packet, length, address, profile, (std::numeric_limits<uint64_t>::max)(), receive_order));
	}

	void release(PacketQueue&, uint64_t, std::vector<PacketNode*>&) override {}

	bool toggle(PacketQueue&) override
	{
		if (phase_ == Phase::dropping)
		{
			phase_ = Phase::holding;
			return false;
		}
		phase_ = Phase::released;
		return true;
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
	enum class Phase
	{
		dropping,
		holding,
		released,
	};

	Phase phase_ = Phase::dropping;
};
}  // namespace

std::unique_ptr<PacketMode> create_drop_until_toggle_mode(const ProfileOptions& options)
{
	return std::make_unique<DropUntilToggleMode>(options);
}
