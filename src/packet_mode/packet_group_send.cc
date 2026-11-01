#include "packet_mode.h"

#include <algorithm>
#include <limits>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "log.h"

LOG_DEFAULT_GROUP(logging::group::profile)

namespace {
class PacketGroupSendMode final : public PacketMode
{
public:
	explicit PacketGroupSendMode(ProfileOptions options)
	: PacketMode(std::move(options), "packet_group_send")
	, random_engine_(std::random_device{}())
	{
	}

	void reset() override
	{
		PacketMode::reset();
		current_group_ = 0;
		next_send_ = 0;
		capturing_ = true;
		send_order_.clear();
		group_packet_counts_.assign(static_cast<size_t>(options_.group_count), 0);
		group_packets_remaining_.assign(static_cast<size_t>(options_.group_count), 0);
		group_packets_sent_.assign(static_cast<size_t>(options_.group_count), 0);
		group_packets_failed_.assign(static_cast<size_t>(options_.group_count), 0);
		group_released_.assign(static_cast<size_t>(options_.group_count), false);
		displayed_group_ = 0;
		status_ = group_status("Capturing", 0);
		LOG_ACTIVATE("Profile '%s': group 1/%d activated; capturing",
					 options_.name.c_str(),
					 options_.group_count);
	}

	void capture_packet(const uint8_t* packet,
						uint32_t length,
						const backend::PacketMeta& address,
						int profile,
						uint64_t now,
						uint64_t receive_order,
						PacketQueue& packets) override
	{
		const uint64_t release_at = capturing_ ? (std::numeric_limits<uint64_t>::max)() : now;
		PacketNode* node = make_packet_node(packet, length, address, profile, release_at, receive_order);
		if (capturing_)
		{
			node->group_index = current_group_;
			node->grouped = true;
			++group_packet_counts_[current_group_];
		}
		packets.push(node);
	}

	void release(PacketQueue& packets, uint64_t now, std::vector<PacketNode*>& ready_packets) override
	{
		collect_due_packets(packets, now, ready_packets);
	}

	bool toggle(PacketQueue& packets) override
	{
		if (capturing_ && current_group_ + 1 < static_cast<size_t>(options_.group_count))
		{
			LOG_INFO("Profile '%s': group %zu/%d capture complete (%zu packets)",
					 options_.name.c_str(),
					 current_group_ + 1,
					 options_.group_count,
					 group_packet_counts_[current_group_]);
			++current_group_;
			displayed_group_ = current_group_;
			status_ = group_status("Capturing", current_group_);
			LOG_ACTIVATE("Profile '%s': group %zu/%d activated; capturing",
						 options_.name.c_str(),
						 current_group_ + 1,
						 options_.group_count);
			return false;
		}

		if (capturing_)
		{
			LOG_INFO("Profile '%s': group %zu/%d capture complete (%zu packets)",
					 options_.name.c_str(),
					 current_group_ + 1,
					 options_.group_count,
					 group_packet_counts_[current_group_]);
			capturing_ = false;
			build_send_order();
		}
		send_next_group(packets);
		return next_send_ == send_order_.size();
	}

	void packet_send_completed(const PacketNode& node, bool succeeded) override
	{
		if (!node.grouped)
			return;
		const size_t group_index = node.group_index;
		if (group_index >= group_released_.size() || !group_released_[group_index] ||
			group_packets_remaining_[group_index] == 0)
			return;
		--group_packets_remaining_[group_index];
		if (succeeded)
			++group_packets_sent_[group_index];
		else
			++group_packets_failed_[group_index];
		if (group_packets_remaining_[group_index] != 0)
			return;

		const size_t sent = group_packets_sent_[group_index];
		const size_t failed = group_packets_failed_[group_index];
		if (failed == 0)
			LOG_ACTIVATE("Profile '%s': group %zu/%d sent (%zu packets)",
						 options_.name.c_str(),
						 group_index + 1,
						 options_.group_count,
						 sent);
		else
			LOG_WARN("Profile '%s': group %zu/%d send completed with %zu sent and %zu failed",
					 options_.name.c_str(),
					 group_index + 1,
					 options_.group_count,
					 sent,
					 failed);
		if (displayed_group_ == group_index && !capturing_)
			status_ = group_status(failed == 0 ? "Sent" : "Send failures", group_index);
	}

	std::string status() const override
	{
		return status_;
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
	void build_send_order()
	{
		send_order_.resize(static_cast<size_t>(options_.group_count));
		for (size_t index = 0; index < send_order_.size(); ++index)
			send_order_[index] = index;
		switch (options_.group_order)
		{
			case PacketGroupOrder::lifo:
				std::reverse(send_order_.begin(), send_order_.end());
				break;
			case PacketGroupOrder::random:
				std::shuffle(send_order_.begin(), send_order_.end(), random_engine_);
				break;
			case PacketGroupOrder::fifo:
			default:
				break;
		}
	}

	void send_next_group(PacketQueue& packets)
	{
		if (next_send_ >= send_order_.size())
			return;
		const size_t group_to_send = send_order_[next_send_++];
		displayed_group_ = group_to_send;
		group_released_[group_to_send] = true;
		group_packets_remaining_[group_to_send] = group_packet_counts_[group_to_send];
		status_ = group_status("Sending", group_to_send);
		LOG_ACTIVATE("Profile '%s': sending group %zu/%d (%s order, %zu packets)",
					 options_.name.c_str(),
					 group_to_send + 1,
					 options_.group_count,
					 options_.group_order == PacketGroupOrder::fifo
						 ? "fifo"
						 : options_.group_order == PacketGroupOrder::lifo ? "lifo" : "random",
					 group_packet_counts_[group_to_send]);
		std::vector<PacketNode*> queued_packets;
		while (!packets.empty())
		{
			queued_packets.push_back(packets.top());
			packets.pop();
		}
		for (PacketNode* node : queued_packets)
		{
			if (node != nullptr && node->grouped && node->group_index == group_to_send)
				node->release_at = 0;
			packets.push(node);
		}
		if (group_packets_remaining_[group_to_send] == 0)
		{
			LOG_ACTIVATE("Profile '%s': group %zu/%d sent (empty group)",
						 options_.name.c_str(),
						 group_to_send + 1,
						 options_.group_count);
			status_ = group_status("Sent", group_to_send);
		}
	}

	std::string group_status(const char* stage, size_t group) const
	{
		return std::string(stage) + " group " + std::to_string(group + 1) + "/" + std::to_string(options_.group_count);
	}

	size_t current_group_ = 0;
	size_t next_send_ = 0;
	size_t displayed_group_ = 0;
	bool capturing_ = true;
	std::string status_;
	std::vector<size_t> send_order_;
	std::vector<size_t> group_packet_counts_;
	std::vector<size_t> group_packets_remaining_;
	std::vector<size_t> group_packets_sent_;
	std::vector<size_t> group_packets_failed_;
	std::vector<bool> group_released_;
	std::mt19937_64 random_engine_;
};
}  // namespace

std::unique_ptr<PacketMode> create_packet_group_send_mode(const ProfileOptions& options)
{
	return std::make_unique<PacketGroupSendMode>(options);
}
