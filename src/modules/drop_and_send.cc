#include "packet_mode.h"

#include <algorithm>

#include "log.h"

namespace {
class DropAndSendMode final : public PacketMode
{
public:
	explicit DropAndSendMode(ProfileOptions options) : PacketMode(std::move(options), "drop_and_send") {}

	void capture(const BYTE*			  packet,
				 UINT					  length,
				 const WINDIVERT_ADDRESS& address,
				 int					  profile,
				 uint64_t				  now,
				 uint64_t				  receive_order,
				 PacketQueue&			  packets) override
	{
		profile_			= profile;
		uint64_t release_at = now + static_cast<uint64_t>(options_.delay_ms);
		if (!packets.empty())
			release_at = packets.top()->release_at;
		packets.push(make_packet_node(packet, length, address, profile, release_at, receive_order));
	}

	void release(PacketQueue& packets, uint64_t now, std::vector<PacketNode*>& ready_packets) override
	{
		collect_due_packets(packets, now, ready_packets);
		drop_packets(ready_packets, "delayed");
	}

	void flush(PacketQueue& packets, std::vector<PacketNode*>& pending_packets) override
	{
		while (!packets.empty())
		{
			pending_packets.push_back(packets.top());
			packets.pop();
		}
		drop_packets(pending_packets, "flushed");
	}

private:
	void drop_packets(std::vector<PacketNode*>& packets, const char* source)
	{
		(void)source;
		const size_t	  drop_count	= options_.ratio_percent ? (packets.size() * static_cast<size_t>(options_.ratio) + 99) / 100
																 : (std::min)(packets.size(), static_cast<size_t>(options_.ratio));
		const std::string profile_label = "profile #" + std::to_string(profile_) + " - " + options_.name;
		for (size_t index = 0; index < drop_count; ++index)
		{
			PacketNode* node = packets[index];
			LOG_DEBUG("%s drop: %s packet: Length = %u, Timestamp = %llu",
					  profile_label.c_str(),
					  source,
					  node->length,
					  static_cast<unsigned long long>(node->address->Timestamp));
			destroy_packet_node(node);
		}
		packets.erase(packets.begin(), packets.begin() + drop_count);
	}

	int profile_ = 0;
};
}  // namespace

std::unique_ptr<PacketMode> create_drop_and_send_mode(const ProfileOptions& options)
{
	return std::make_unique<DropAndSendMode>(options);
}
