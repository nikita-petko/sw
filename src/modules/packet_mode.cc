#include "packet_mode.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

#include "log.h"

namespace {
[[maybe_unused]] static
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

bool get_tcp_numbers(const uint8_t* packet, uint32_t length, uint32_t& sequence, uint32_t& acknowledgment)
{
	ParsedPacket parsed;
	if (!parse_packet(packet, length, parsed) || !parsed.tcp)
		return false;
	sequence	   = swap_u32(parsed.tcp->SeqNum);
	acknowledgment = swap_u32(parsed.tcp->AckNum);
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

void PacketMode::prepare_packet_for_send(uint8_t* packet, uint32_t length, const backend::PacketMeta* address)
{
	if (!options_.ack_restoration)
		return;
	(void)address;

	ParsedPacket parsed;
	if (!parse_packet(packet, length, parsed) || !parsed.tcp || !parsed.tcp->Ack)
		return;
	TcpHeader* tcp_header = parsed.tcp;

	std::string flow;
	if (parsed.ipv4)
	{
		flow.append(reinterpret_cast<const char*>(&parsed.ipv4->SrcAddr), sizeof(parsed.ipv4->SrcAddr));
		flow.append(reinterpret_cast<const char*>(&parsed.ipv4->DstAddr), sizeof(parsed.ipv4->DstAddr));
	}
	else if (parsed.ipv6)
	{
		flow.append(reinterpret_cast<const char*>(parsed.ipv6->SrcAddr), sizeof(parsed.ipv6->SrcAddr));
		flow.append(reinterpret_cast<const char*>(parsed.ipv6->DstAddr), sizeof(parsed.ipv6->DstAddr));
	}
	flow.append(reinterpret_cast<const char*>(&tcp_header->SrcPort), sizeof(tcp_header->SrcPort));
	flow.append(reinterpret_cast<const char*>(&tcp_header->DstPort), sizeof(tcp_header->DstPort));
	const auto last_sent = last_sent_ack_.find(flow);
	const bool has_last	 = last_sent != last_sent_ack_.end();

	uint32_t acknowledgment = swap_u32(tcp_header->AckNum);
	if (tcp_header->Psh && has_last && acknowledgment < last_sent->second)
	{
		acknowledgment	   = last_sent->second;
		tcp_header->AckNum = swap_u32(acknowledgment);
		backend::calc_checksums(packet, length);
	}
	if (!has_last || acknowledgment > last_sent->second)
		last_sent_ack_[flow] = acknowledgment;
}

void PacketMode::capture(const uint8_t*				 packet,
						 uint32_t					 length,
						 const backend::PacketMeta& address,
						 int						 profile,
						 uint64_t					 now,
						 uint64_t					 receive_order,
						 PacketQueue&				 packets)
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
					discard(address);
					return;
				}
			}
		}
	}
	if (options_.ack_restoration)
	{
		ParsedPacket parsed;
		if (parse_packet(packet, length, parsed) && parsed.tcp && parsed.tcp->Ack && !parsed.tcp->Psh)
		{
			packets.push(make_packet_node(packet, length, address, profile, now, receive_order));
			return;
		}
	}
	capture_packet(packet, length, address, profile, now, receive_order, packets);
}

PacketNode* make_packet_node(const uint8_t*				   packet,
							 uint32_t					   length,
							 const backend::PacketMeta& address,
							 int						   profile,
							 uint64_t					   release_at,
							 uint64_t					   receive_order)
{
	PacketNode* node	= new PacketNode;
	node->packet		= new uint8_t[length];
	node->length		= length;
	node->address		= new backend::PacketMeta(address);
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
