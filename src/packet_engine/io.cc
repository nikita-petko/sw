#include "internal.h"

#include <cstdlib>
#include <ctime>

#include "log.h"

namespace {
void log_received_packet([[maybe_unused]] const std::string& profile_label, const uint8_t* packet_data, uint32_t received_length)
{
	ParsedPacket		  parsed;
	const PacketAddresses addresses = packet_addresses(packet_data, received_length);
	if (parse_packet(packet_data, received_length, parsed) && parsed.tcp != nullptr)
	{
		const TcpHeader* tcp_header = parsed.tcp;
		(void)tcp_header;
		LOG_DEBUG_GROUP(logging::group::packet_recv, "%s recv: TCP packet: Length = %u, Flags = %s, Sequence = %u, Ack = %u, Src = %s, Dst = %s",
				  profile_label.c_str(),
				  received_length,
				  format_tcp_flags(*tcp_header).c_str(),
				  swap_u32(tcp_header->SeqNum),
				  swap_u32(tcp_header->AckNum),
				  addresses.source.c_str(),
				  addresses.destination.c_str());
	}
	else
	{
		LOG_DEBUG_GROUP(logging::group::packet_recv, "%s recv: packet: Length = %u, Src = %s, Dst = %s",
				  profile_label.c_str(),
				  received_length,
				  addresses.source.c_str(),
				  addresses.destination.c_str());
	}
}

/// Sends a packet the mode released and logs the outcome. `failure` and `success` name the situation in the log
/// ("send: failed" / "send: delayed packet", or the flush variants). Returns the number of bytes sent.
uint32_t transmit_packet(PacketMode&				mode,
						 backend::PacketChannel&	handle,
						 PacketNode*				node,
						 const std::string&			profile_label,
						 const char*				failure,
						 [[maybe_unused]] const char* success,
						 std::atomic<uint64_t>&		sent_counter)
{
	uint32_t	sent = 0;
	std::string io_error;
	mode.prepare_packet_for_send(node->packet, node->length, node->address);
	if (handle.send(node->packet, node->length, *node->address, sent, io_error) != backend::IoStatus::ok)
	{
		LOG_ERROR("%s %s: %s", profile_label.c_str(), failure, io_error.c_str());
	}
	else if (sent != 0)
	{
		sent_counter.fetch_add(1);
		const PacketAddresses				  addresses = packet_addresses(node->packet, node->length);
		ParsedPacket						  parsed;
		[[maybe_unused]] const bool			  has_tcp_header = parse_packet(node->packet, node->length, parsed) && parsed.tcp != nullptr;
		[[maybe_unused]] const TcpHeader*	  tcp_header	 = parsed.tcp;
		LOG_DEBUG_GROUP(logging::group::packet_send, "%s %s: Length = %u, Flags = %s, Src = %s, Dst = %s, SendLen = %u",
				  profile_label.c_str(),
				  success,
				  node->length,
				  has_tcp_header ? format_tcp_flags(*tcp_header).c_str() : "-",
				  addresses.source.c_str(),
				  addresses.destination.c_str(),
				  sent);
	}
	return sent;
}
}  // namespace

void PacketEngine::read_packets(const std::shared_ptr<Session>& session)
{
	const int			  profile		  = session->profile;
	const ProfileOptions& profile_options = options_.profiles[profile - 1];
	const std::string	  profile_label	  = "profile #" + std::to_string(profile) + " - " + profile_options.name;
	while (!session->stopping)
	{
		uint8_t			 packet_data[0xFFFF];
		backend::PacketMeta address;
		uint32_t		 received_length = 0;
		std::string		 io_error;
		const backend::IoStatus status = session->handle->recv(packet_data, sizeof(packet_data), received_length, address, io_error);
		if (status != backend::IoStatus::ok)
		{
			if (status == backend::IoStatus::error && !session->stopping)
				LOG_ERROR("%s recv: %s", profile_label.c_str(), io_error.c_str());
			continue;
		}
		state_->profile_stats[profile - 1].packets_caught.fetch_add(1);
#ifdef LAGSW_FEATURE_PCAP_FILES
		if (session->pcap.file)
			record_pcap_packet(session->pcap, packet_data, received_length, profile_label);
#endif
		const bool sniff = profile_options.capture_options.sniff.value_or(false);
		if (!sniff)
		{
			std::lock_guard<std::mutex> lock(session->packet_mutex);
			if (session->stopping)
				break;
			session->mode->capture(packet_data,
								   received_length,
								   address,
								   session->profile,
								   platform::tick_ms(),
								   session->next_receive_order++,
								   session->delayed_packets);
			session->packet_changed.notify_one();
		}
		log_received_packet(profile_label, packet_data, received_length);
	}
}

void PacketEngine::write_packets(const std::shared_ptr<Session>& session)
{
	const ProfileOptions& profile_options = options_.profiles[session->profile - 1];
	const std::string	  profile_label	  = "profile #" + std::to_string(session->profile) + " - " + profile_options.name;
	State::ProfileStats&  stats			  = state_->profile_stats[session->profile - 1];
	// The loop ends only once the session is stopping; the flush below must run even when that happens before the first iteration.
	{
		while (!session->stopping)
		{
			std::vector<PacketNode*> ready_packets;
			{
				std::unique_lock<std::mutex> lock(session->packet_mutex);
				while (session->delayed_packets.empty() && !session->stopping)
					session->packet_changed.wait(lock);
				if (session->stopping)
					break;

				const uint64_t now = platform::tick_ms();
				if (session->delayed_packets.top()->release_at > now)
				{
					if (session->delayed_packets.top()->release_at == (std::numeric_limits<uint64_t>::max)())
						session->packet_changed.wait(lock);
					else
					{
						const uint64_t wait_ms = session->delayed_packets.top()->release_at - now;
						session->packet_changed.wait_for(lock, std::chrono::milliseconds(wait_ms));
					}
					continue;
				}
				session->mode->release(session->delayed_packets, now, ready_packets);
			}
			for (PacketNode* node : ready_packets)
			{
				const uint32_t sent = transmit_packet(
					*session->mode, *session->handle, node, profile_label, "send: failed", "send: delayed packet", stats.delayed_packets_sent);
				std::lock_guard<std::mutex> packet_lock(session->packet_mutex);
				session->mode->packet_send_completed(*node, sent != 0);
			}
			for (PacketNode* node : ready_packets)
				destroy_packet_node(node);
		}

		std::vector<PacketNode*> pending_packets;
		{
			std::lock_guard<std::mutex> lock(session->packet_mutex);
			session->mode->flush(session->delayed_packets, pending_packets);
		}
		for (PacketNode* node : pending_packets)
		{
			transmit_packet(*session->mode, *session->handle, node, profile_label, "flush: send failed", "flush: sent packet", stats.teardown_packets_sent);
			destroy_packet_node(node);
		}
	}
	LOG_DEBUG_GROUP(logging::group::packet_send, "%s flush: stopped", profile_label.c_str());
}
