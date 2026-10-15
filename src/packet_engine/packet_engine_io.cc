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
		BYTE			  packet_data[0xFFFF];
		WINDIVERT_ADDRESS address;
		UINT			  received_length = 0;
		if (!WinDivertRecv(session->handle, packet_data, sizeof(packet_data), &received_length, &address))
		{
			const DWORD error = GetLastError();
			if (!session->stopping && error != ERROR_INVALID_HANDLE && error != ERROR_OPERATION_ABORTED)
				LOG_ERROR("%s recv: WinDivertRecv error %lu: %s", profile_label.c_str(), error, format_win32_error(error).c_str());
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
		const bool sniff = profile_options.windivert_options.sniff.value_or(false);
		if (!sniff)
		{
			std::lock_guard<std::mutex> lock(session->packet_mutex);
			if (session->stopping)
				break;
			session->mode->capture(packet_data,
								   received_length,
								   address,
								   session->profile,
								   GetTickCount64(),
								   session->next_receive_order++,
								   session->delayed_packets);
			session->packet_changed.notify_one();
		}
		PWINDIVERT_TCPHDR	  tcp_header = nullptr;
		const PacketAddresses addresses	 = packet_addresses(packet_data, received_length);
		if (WinDivertHelperParsePacket(packet_data,
									   received_length,
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
			tcp_header != nullptr)
		{
			LOG_DEBUG("%s recv: TCP packet: Length = %u, Flags = %s, Sequence = %u, Ack = %u, Src = %s, Dst = %s",
					  profile_label.c_str(),
					  received_length,
					  format_tcp_flags(*tcp_header).c_str(),
					  WinDivertHelperNtohl(tcp_header->SeqNum),
					  WinDivertHelperNtohl(tcp_header->AckNum),
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

				const uint64_t now = GetTickCount64();
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
				UINT sent = 0;
				session->mode->prepare_packet_for_send(node->packet, node->length, node->address);
				if (!WinDivertSend(session->handle, node->packet, node->length, &sent, node->address))
				{
					const DWORD error = GetLastError();
					LOG_ERROR("%s send: WinDivertSend failed %lu: %s", profile_label.c_str(), error, format_win32_error(error).c_str());
				}
				else if (sent != 0)
				{
					state_->profile_stats[session->profile - 1].delayed_packets_sent.fetch_add(1);
					const PacketAddresses addresses		 = packet_addresses(node->packet, node->length);
					PWINDIVERT_TCPHDR	  tcp_header	 = nullptr;
					const bool			  has_tcp_header = WinDivertHelperParsePacket(node->packet,
																					  node->length,
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
														   tcp_header != nullptr;

#ifdef NDEBUG
					// Suppress warning for unused variable 'has_tcp_header' in release builds
					(void)has_tcp_header;
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
			UINT sent = 0;
			session->mode->prepare_packet_for_send(node->packet, node->length, node->address);
			if (!WinDivertSend(session->handle, node->packet, node->length, &sent, node->address))
			{
				const DWORD error = GetLastError();
				LOG_ERROR("%s flush: WinDivertSend failed %lu: %s", profile_label.c_str(), error, format_win32_error(error).c_str());
			}
			else if (sent != 0)
			{
				state_->profile_stats[session->profile - 1].teardown_packets_sent.fetch_add(1);
				const PacketAddresses addresses		 = packet_addresses(node->packet, node->length);
				PWINDIVERT_TCPHDR	  tcp_header	 = nullptr;
				const bool			  has_tcp_header = WinDivertHelperParsePacket(node->packet,
																				  node->length,
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
													   tcp_header != nullptr;

#ifdef NDEBUG
				// Suppress warning for unused variable 'has_tcp_header' in release builds
				(void)has_tcp_header;
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
