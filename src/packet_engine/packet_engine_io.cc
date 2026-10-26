#include "packet_engine_internal.h"

#include <cstdlib>
#include <ctime>

#include "log.h"

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
		if (session->pcap_file)
		{
			std::ofstream& pcap_file	= *session->pcap_file;
			const auto	   now			= std::chrono::system_clock::now().time_since_epoch();
			const auto	   seconds		= std::chrono::duration_cast<std::chrono::seconds>(now);
			const auto	   microseconds = std::chrono::duration_cast<std::chrono::microseconds>(now - seconds);
			write_pcap_u32(pcap_file, static_cast<uint32_t>(seconds.count()));
			write_pcap_u32(pcap_file, static_cast<uint32_t>(microseconds.count()));
			write_pcap_u32(pcap_file, received_length);
			write_pcap_u32(pcap_file, received_length);
			pcap_file.write(reinterpret_cast<const char*>(packet_data), received_length);
			if (!pcap_file)
			{
				LOG_ERROR("%s PCAP capture: failed to write %s", profile_label.c_str(), session->pcap_path.c_str());
				session->pcap_file.reset();
			}
		}
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
		ParsedPacket		  parsed;
		const PacketAddresses addresses = packet_addresses(packet_data, received_length);
		if (parse_packet(packet_data, received_length, parsed) && parsed.tcp != nullptr)
		{
			const TcpHeader* tcp_header = parsed.tcp;
			(void)tcp_header;
			LOG_DEBUG("%s recv: TCP packet: Length = %u, Flags = %s, Sequence = %u, Ack = %u, Src = %s, Dst = %s",
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
			LOG_DEBUG("%s recv: packet: Length = %u, Src = %s, Dst = %s",
					  profile_label.c_str(),
					  received_length,
					  addresses.source.c_str(),
					  addresses.destination.c_str());
		}
	}
}

void PacketEngine::write_packets(const std::shared_ptr<Session>& session)

{
	const ProfileOptions& profile_options = options_.profiles[session->profile - 1];
	const std::string	  profile_label	  = "profile #" + std::to_string(session->profile) + " - " + profile_options.name;
	while (!session->stopping)
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
				uint32_t	sent = 0;
				std::string io_error;
				session->mode->prepare_packet_for_send(node->packet, node->length, node->address);
				if (session->handle->send(node->packet, node->length, *node->address, sent, io_error) != backend::IoStatus::ok)
				{
					LOG_ERROR("%s send: failed: %s", profile_label.c_str(), io_error.c_str());
				}
				else if (sent != 0)
				{
					state_->profile_stats[session->profile - 1].delayed_packets_sent.fetch_add(1);
					const PacketAddresses addresses = packet_addresses(node->packet, node->length);
					ParsedPacket		  parsed;
					const bool			  has_tcp_header = parse_packet(node->packet, node->length, parsed) && parsed.tcp != nullptr;
					const TcpHeader*	  tcp_header	 = parsed.tcp;
#ifdef NDEBUG
					// Suppress warning for unused variable 'has_tcp_header' in release builds
					(void)has_tcp_header;
					(void)tcp_header;
#endif

					LOG_DEBUG("%s send: delayed packet: Length = %u, Flags = %s, Src = %s, Dst = %s, SendLen = %u",
							  profile_label.c_str(),
							  node->length,
							  has_tcp_header ? format_tcp_flags(*tcp_header).c_str() : "-",
							  addresses.source.c_str(),
							  addresses.destination.c_str(),
							  sent);
				}
				{
					std::lock_guard<std::mutex> packet_lock(session->packet_mutex);
					session->mode->packet_send_completed(*node, sent != 0);
				}
			}
			for (size_t index = 0; index < ready_packets.size(); ++index)
			{
				PacketNode* node = ready_packets[index];
				destroy_packet_node(node);
			}
		}

		std::vector<PacketNode*> pending_packets;
		{
			std::lock_guard<std::mutex> lock(session->packet_mutex);
			session->mode->flush(session->delayed_packets, pending_packets);
		}
		for (PacketNode* node : pending_packets)
		{
			uint32_t	sent = 0;
			std::string io_error;
			session->mode->prepare_packet_for_send(node->packet, node->length, node->address);
			if (session->handle->send(node->packet, node->length, *node->address, sent, io_error) != backend::IoStatus::ok)
			{
				LOG_ERROR("%s flush: send failed: %s", profile_label.c_str(), io_error.c_str());
			}
			else if (sent != 0)
			{
				state_->profile_stats[session->profile - 1].teardown_packets_sent.fetch_add(1);
				const PacketAddresses addresses = packet_addresses(node->packet, node->length);
				ParsedPacket		  parsed;
				const bool			  has_tcp_header = parse_packet(node->packet, node->length, parsed) && parsed.tcp != nullptr;
				const TcpHeader*	  tcp_header	 = parsed.tcp;
#ifdef NDEBUG
				// Suppress warning for unused variable 'has_tcp_header' in release builds
				(void)has_tcp_header;
				(void)tcp_header;
#endif

				LOG_DEBUG("%s flush: sent packet: Length = %u, Flags = %s, Src = %s, Dst = %s, SendLen = %u",
						  profile_label.c_str(),
						  node->length,
						  has_tcp_header ? format_tcp_flags(*tcp_header).c_str() : "-",
						  addresses.source.c_str(),
						  addresses.destination.c_str(),
						  sent);
			}
			destroy_packet_node(node);
		}
	}
	LOG_DEBUG("%s flush: stopped", profile_label.c_str());
}
