#include "packet_mode.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

#include "log.h"

namespace {
const char* retransmission_mode_name(RetransmissionMode mode)
{
	switch (mode)
	{
		case RetransmissionMode::none:
			return "none";
		case RetransmissionMode::only_seq:
			return "only_seq";
		case RetransmissionMode::only_ack:
			return "only_ack";
		case RetransmissionMode::both:
			return "both";
	}
	return "unknown";
}
}  // namespace

bool get_tcp_numbers(const BYTE* packet, UINT length, uint32_t& sequence, uint32_t& acknowledgment)
{
	WINDIVERT_TCPHDR* tcp_header = nullptr;
	if (!WinDivertHelperParsePacket(packet,
									length,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									&tcp_header,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr) ||
		!tcp_header)
		return false;
	sequence	   = WinDivertHelperNtohl(tcp_header->SeqNum);
	acknowledgment = WinDivertHelperNtohl(tcp_header->AckNum);
	return true;
}

PacketMode::PacketMode(ProfileOptions options, const char* mode_name) : options_(std::move(options)), mode_name_(mode_name)
{
	LOG_DEBUG("packet mode init: %s (%s)", mode_name_, options_.name.c_str());
}

PacketMode::~PacketMode()
{
	LOG_DEBUG("packet mode deinit: %s (%s)", mode_name_, options_.name.c_str());
}

void PacketMode::prepare_packet_for_send(BYTE* packet, UINT length, const WINDIVERT_ADDRESS* address)
{
	if (!options_.ack_restoration)
		return;
	const size_t direction = address != nullptr && address->Outbound ? 1 : 0;

	PWINDIVERT_TCPHDR tcp_header = nullptr;
	if (!WinDivertHelperParsePacket(packet,
									length,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									&tcp_header,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr) ||
		!tcp_header || !tcp_header->Ack)
		return;

	uint32_t acknowledgment = WinDivertHelperNtohl(tcp_header->AckNum);
	if (tcp_header->Psh && has_last_sent_ack_[direction] && acknowledgment < last_sent_ack_[direction])
	{
		acknowledgment	   = last_sent_ack_[direction];
		tcp_header->AckNum = WinDivertHelperHtonl(acknowledgment);
		WinDivertHelperCalcChecksums(packet, length, nullptr, 0);
	}
	if (!has_last_sent_ack_[direction] || acknowledgment > last_sent_ack_[direction])
	{
		last_sent_ack_[direction]	  = acknowledgment;
		has_last_sent_ack_[direction] = true;
	}
}

void PacketMode::capture(const BYTE*			  packet,
						 UINT					  length,
						 const WINDIVERT_ADDRESS& address,
						 int					  profile,
						 uint64_t				  now,
						 uint64_t				  receive_order,
						 PacketQueue&			  packets)
{
	if (options_.retransmission_mode != RetransmissionMode::none)
	{
		uint32_t sequence		= 0;
		uint32_t acknowledgment = 0;
		if (get_tcp_numbers(packet, length, sequence, acknowledgment))
		{
			PacketQueue queued_packets = packets;
			while (!queued_packets.empty())
			{
				const PacketNode* queued = queued_packets.top();
				queued_packets.pop();
				if (!queued || !queued->packet)
					continue;
				uint32_t queued_sequence	   = 0;
				uint32_t queued_acknowledgment = 0;
				if (!get_tcp_numbers(queued->packet, queued->length, queued_sequence, queued_acknowledgment))
					continue;
				const bool duplicate = options_.retransmission_mode == RetransmissionMode::only_seq ? sequence == queued_sequence
									   : options_.retransmission_mode == RetransmissionMode::only_ack
										   ? acknowledgment == queued_acknowledgment
										   : sequence == queued_sequence && acknowledgment == queued_acknowledgment;
				if (duplicate)
				{
					LOG_DEBUG("profile #%d - %s drop: duplicate TCP retransmission (mode = %s, sequence = %u, ack = %u)",
							  profile,
							  options_.name.c_str(),
							  retransmission_mode_name(options_.retransmission_mode),
							  sequence,
							  acknowledgment);
					return;
				}
			}
		}
	}
	if (options_.ack_restoration)
	{
		PWINDIVERT_TCPHDR tcp_header = nullptr;
		if (WinDivertHelperParsePacket(packet,
									   length,
									   nullptr,
									   nullptr,
									   nullptr,
									   nullptr,
									   nullptr,
									   &tcp_header,
									   nullptr,
									   nullptr,
									   nullptr,
									   nullptr,
									   nullptr) &&
			tcp_header && tcp_header->Ack && !tcp_header->Psh)
		{
			packets.push(make_packet_node(packet, length, address, profile, now, receive_order));
			return;
		}
	}
	capture_packet(packet, length, address, profile, now, receive_order, packets);
}

PacketNode* make_packet_node(const BYTE*			  packet,
							 UINT					  length,
							 const WINDIVERT_ADDRESS& address,
							 int					  profile,
							 uint64_t				  release_at,
							 uint64_t				  receive_order)
{
	PacketNode* node	= new PacketNode;
	node->packet		= new BYTE[length];
	node->length		= length;
	node->address		= new WINDIVERT_ADDRESS(address);
	node->profile		= profile;
	node->release_at	= release_at;
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
