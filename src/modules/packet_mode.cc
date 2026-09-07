#include "packet_mode.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

#include "log.h"

PacketMode::PacketMode(ProfileOptions options, const char* mode_name)
	: options_(std::move(options)), mode_name_(mode_name)
{
	LOG_DEBUG("packet mode init: %s (%s)", mode_name_, options_.name.c_str());
}

PacketMode::~PacketMode()
{
	LOG_DEBUG("packet mode deinit: %s (%s)", mode_name_, options_.name.c_str());
}

PacketNode* make_packet_node(const BYTE* packet,
	UINT length,
	const WINDIVERT_ADDRESS& address,
	int profile,
	uint64_t release_at,
	uint64_t receive_order)
{
	PacketNode* node = new PacketNode;
	node->packet = new BYTE[length];
	node->length = length;
	node->address = new WINDIVERT_ADDRESS(address);
	node->profile = profile;
	node->release_at = release_at;
	node->receive_order = receive_order;
	std::memcpy(node->packet, packet, length);
	return node;
}

void destroy_packet_node(PacketNode* node)
{
	if (!node)
		return;
	delete[] node->packet;
	delete node->address;
	delete node;
}

void collect_due_packets(PacketQueue& packets, uint64_t now, std::vector<PacketNode*>& ready_packets)
{
	while (!packets.empty())
	{
		PacketNode* node = packets.top();
		if (node == nullptr || node->address == nullptr)
		{
			packets.pop();
			destroy_packet_node(node);
			continue;
		}
		if (node->release_at > now)
			break;
		packets.pop();
		ready_packets.push_back(node);
	}
}
