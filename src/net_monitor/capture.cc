// Capture thread of the net monitor: parses sniffed packets into per-server, per-flow and per-port statistics.
#include "net_monitor.h"

#ifdef LAGSW_FEATURE_NET_MONITOR

#	include <algorithm>
#	include <cmath>

#	include "internal.h"
#	include "packet_engine_util.h"
#	include "packet_headers.h"
#	include "platform.h"

using namespace net_monitor_detail;

void NetMonitor::capture_loop()
{
	std::vector<uint8_t> buffer(0xFFFF);
	while (!stopping_)
	{
		backend::PacketMeta		meta;
		uint32_t				length = 0;
		std::string				error;
		const backend::IoStatus status = channel_->recv(buffer.data(), static_cast<uint32_t>(buffer.size()), length, meta, error);
		if (status == backend::IoStatus::closed)
			break;
		if (status != backend::IoStatus::ok)
		{
			if (!stopping_)
			{
				{
					std::lock_guard<std::mutex> lock(mutex_);
					++capture_errors_;
					open_error_ = "capture error: " + error;
				}
				platform::sleep_ms(10);
			}
			continue;
		}
		if (!paused_)
			record(buffer.data(), length);
	}
}

void NetMonitor::record(const uint8_t* packet, uint32_t length)
{
	ParsedPacket parsed;
	if (!parse_packet(packet, length, parsed))
	{
		std::lock_guard<std::mutex> lock(mutex_);
		++unparsed_packets_;
		return;
	}
	const auto now = Clock::now();

	std::lock_guard<std::mutex> lock(mutex_);
	++total_packets_;
	// The direction comes from which endpoint is the server: the backend flag is unreliable for forwarded traffic,
	// which the nfqueue backend always reports as outbound.
	bool outbound = false;
	auto found	  = servers_.find(endpoint_address(parsed, false));
	if (found == servers_.end())
	{
		found	 = servers_.find(endpoint_address(parsed, true));
		outbound = true;
	}
	if (found == servers_.end())
	{
		++other_packets_;
		return;
	}
	ServerStats& stats	   = found->second;
	const uint16_t server_port = parsed.tcp ? swap_u16(outbound ? parsed.tcp->DstPort : parsed.tcp->SrcPort)
								 : parsed.udp ? swap_u16(outbound ? parsed.udp->DstPort : parsed.udp->SrcPort)
											  : 0;
	bool measured = true;
#	ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	const uint16_t main_port = options_.features.server_discovery.port;
	if (main_port != 0)
		measured = server_port == main_port;
#	endif
#	ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	const uint16_t probe_port = options_.features.region_enforcement.probe_port;
	if (probe_port != 0 && server_port == probe_port)
		measured = false;
#	endif
	Direction&	 direction = outbound ? stats.up : stats.down;
	++direction.packets;
	++direction.packets_tick;
	direction.bytes += length;
	direction.bytes_tick += length;
	++(outbound ? size_up_ : size_down_)[size_bucket(length)];

	if (!outbound)
	{
		int ttl = -1, tos = 0;
		if (parsed.ipv4)
		{
			ttl = parsed.ipv4->TTL;
			tos = parsed.ipv4->TOS;
		}
		else if (parsed.ipv6)
		{
			ttl = parsed.ipv6->HopLimit;
			tos = (parsed.ipv6->TrafficClass0 << 4) | parsed.ipv6->TrafficClass1;
		}
		if (ttl >= 0)
		{
			if (stats.last_ttl >= 0 && stats.last_ttl != ttl)
				++stats.ttl_changes;
			stats.last_ttl = ttl;
			if (stats.last_dscp >= 0 && stats.last_dscp != (tos >> 2))
				++stats.dscp_changes;
			stats.last_dscp = tos >> 2;
			if ((tos & 3) == 3)
				++stats.ecn_marked;
		}
	}

	PortStats* port_stats = nullptr;
	if (parsed.tcp || parsed.udp)
	{
		const uint32_t port_key	   = (parsed.tcp ? 1u << 16 : 0u) | server_port;
		auto		   port_found  = ports_.find(port_key);
		if (port_found == ports_.end() && ports_.size() < kMaxPorts)
		{
			port_found				= ports_.emplace(port_key, PortStats{}).first;
			port_found->second.tcp	= parsed.tcp != nullptr;
			port_found->second.port = server_port;
		}
		if (port_found != ports_.end())
		{
			port_stats				  = &port_found->second;
			Direction& port_direction = outbound ? port_stats->up : port_stats->down;
			++port_direction.packets;
			++port_direction.packets_tick;
			port_direction.bytes += length;
			port_direction.bytes_tick += length;
		}
	}

	if (!outbound && measured)
	{
		if (stats.has_in)
		{
			const double gap	  = elapsed_ms(stats.last_in, now);
			stats.max_gap_ms	  = std::max(stats.max_gap_ms, gap);
			stats.tick_max_gap_ms = std::max(stats.tick_max_gap_ms, gap);
			if (gap >= kStallMs)
				++stats.stalls;
			if (stats.prev_gap_ms > 0)
				stats.interarrival_jitter_ms += (std::fabs(gap - stats.prev_gap_ms) - stats.interarrival_jitter_ms) / 16.0;
			stats.prev_gap_ms = gap;
		}
		stats.last_in = now;
		stats.has_in  = true;
		stats.has_silence = true;
	}
	else if (outbound && measured)
	{
		stats.last_out = now;
		stats.has_out  = true;
	}

	// Evicts the least useful flow when the server already tracks as many as it may: closed ones first, then the longest idle.
	const auto make_room = [&](uint64_t key) {
		if (stats.flows.size() < kMaxFlowsPerServer || stats.flows.count(key))
			return;
		auto victim = stats.flows.begin();
		for (auto it = stats.flows.begin(); it != stats.flows.end(); ++it)
			if ((it->second.closed && !victim->second.closed) ||
				(it->second.closed == victim->second.closed && it->second.last_seen < victim->second.last_seen))
				victim = it;
		stats.flows.erase(victim);
	};
	// Counts the packet for its flow; a new flow gets its identity here.
	const auto touch = [&](Flow& flow, bool tcp, uint16_t client_port, uint16_t server_port) {
		if (flow.packets_up + flow.packets_down == 0)
		{
			flow.tcp		 = tcp;
			flow.client_port = client_port;
			flow.server_port = server_port;
			flow.first_seen	 = now;
		}
		flow.last_seen = now;
		(outbound ? flow.packets_up : flow.packets_down) += 1;
		(outbound ? flow.bytes_up : flow.bytes_down) += length;
		(outbound ? flow.bytes_up_tick : flow.bytes_down_tick) += length;
	};

	if (parsed.udp)
	{
		++stats.udp_packets;
		const uint16_t source = swap_u16(parsed.udp->SrcPort);
		const uint16_t dest	  = swap_u16(parsed.udp->DstPort);
		const uint16_t client = outbound ? source : dest;
		const uint16_t server = outbound ? dest : source;
		const uint64_t key	  = (uint64_t{1} << 32) | (static_cast<uint64_t>(client) << 16) | server;
		make_room(key);
		touch(stats.flows[key], false, client, server);
		return;
	}
	if (!parsed.tcp)
		return;
	++stats.tcp_packets;

	const TcpHeader& tcp	= *parsed.tcp;
	const uint16_t	 source = swap_u16(tcp.SrcPort);
	const uint16_t	 dest	= swap_u16(tcp.DstPort);
	const uint64_t	 key	= outbound ? (static_cast<uint64_t>(source) << 16 | dest) : (static_cast<uint64_t>(dest) << 16 | source);
	make_room(key);
	auto existing = stats.flows.find(key);
	// A new SYN on a closed 4-tuple starts a fresh connection that reuses the port.
	if (existing != stats.flows.end() && existing->second.closed && tcp.Syn && !tcp.Ack)
	{
		stats.flows.erase(existing);
		existing = stats.flows.end();
	}
	if (existing == stats.flows.end())
	{
		++stats.flows_opened;
		++stats.flows_tick;
	}
	Flow& flow = stats.flows[key];
	touch(flow, true, outbound ? source : dest, outbound ? dest : source);
	const uint32_t seq	   = swap_u32(tcp.SeqNum);
	const uint32_t payload = payload_length(parsed, length);
	const uint32_t end_seq	  = seq + payload + tcp.Syn + tcp.Fin;
	const bool	   was_closed = flow.closed;

	if (tcp.Rst)
	{
		++stats.resets;
		flow.closed = true;
		flow.reset	= true;
	}
	if (tcp.Syn)
		++stats.syn_packets;
	if (tcp.Fin)
	{
		++stats.fin_packets;
		(outbound ? flow.fin_out : flow.fin_in) = true;
		if (flow.fin_out && flow.fin_in)
			flow.closed = true;
	}
	if (!was_closed && flow.closed)
		flow.closed_at = now;
	if (tcp.Psh)
		++stats.psh_packets;
	if (payload == 0 && !tcp.Syn && !tcp.Fin && !tcp.Rst && tcp.Ack)
	{
		++stats.pure_acks;
		// The same acknowledgment repeated without data and with an open window means the peer is missing a segment.
		const uint32_t ack_number = swap_u32(tcp.AckNum);
		bool&		   seen		  = outbound ? flow.ack_out_seen : flow.ack_in_seen;
		uint32_t&	   last		  = outbound ? flow.last_ack_out : flow.last_ack_in;
		if (seen && last == ack_number && tcp.Window != 0 && (outbound ? flow.in_seen : !flow.pending.empty()))
			++(outbound ? stats.dup_acks_up : stats.dup_acks_down);
		seen = true;
		last = ack_number;
	}
	if (!outbound && tcp.Window == 0 && !tcp.Rst && !tcp.Syn)
		++stats.zero_windows;

	if (outbound && tcp.Syn && !tcp.Ack)
	{
		if (flow.syn_pending)
			++stats.syn_retries;
		flow.syn_pending = true;
		flow.syn_sent	 = now;
	}
	else if (!outbound && tcp.Syn && tcp.Ack && flow.syn_pending)
	{
		const double handshake = elapsed_ms(flow.syn_sent, now);
		flow.syn_pending	   = false;
		if (stats.handshakes == 0)
			stats.handshake_min_ms = stats.handshake_max_ms = handshake;
		stats.handshake_min_ms	= std::min(stats.handshake_min_ms, handshake);
		stats.handshake_max_ms	= std::max(stats.handshake_max_ms, handshake);
		stats.last_handshake_ms = handshake;
		stats.handshake_sum_ms += handshake;
		++stats.handshakes;
	}

	if (outbound)
	{
		if (end_seq == seq)
			return;
		if (payload > 0 && measured)
			++stats.data_up;
		if (flow.out_seen && !seq_gt(end_seq, flow.highest_out_end))
		{
			// A retransmission makes any ACK for these bytes ambiguous, so they must not produce an RTT sample.
			if (measured)
				++stats.retrans_up;
			while (!flow.pending.empty() && !seq_gt(flow.pending.front().end_seq, end_seq))
				flow.pending.pop_front();
			return;
		}
		flow.out_seen		 = true;
		flow.highest_out_end = end_seq;
		flow.pending.push_back({end_seq, now});
		if (flow.pending.size() > kPendingPerFlow)
			flow.pending.pop_front();
		return;
	}

	if (payload > 0 && measured)
		++stats.data_down;
	if (end_seq != seq)
	{
		if (flow.in_seen && !seq_gt(end_seq, flow.highest_in_end))
		{
			if (measured)
				++stats.retrans_down;
		}
		else
		{
			flow.in_seen		= true;
			flow.highest_in_end = end_seq;
		}
	}
	if (!tcp.Ack)
		return;
	const uint32_t	  ack	  = swap_u32(tcp.AckNum);
	bool			  matched = false;
	Clock::time_point sent;
	while (!flow.pending.empty() && !seq_gt(flow.pending.front().end_seq, ack))
	{
		sent	= flow.pending.front().sent;
		matched = true;
		flow.pending.pop_front();
	}
	if (!matched)
		return;
	const double rtt = elapsed_ms(sent, now);
	++flow.rtt_samples;
	flow.rtt_sum_ms += rtt;
	flow.last_rtt_ms = rtt;
	flow.rtt_tick_sum_ms += rtt;
	++flow.rtt_tick_count;
	if (port_stats)
	{
		++port_stats->rtt_samples;
		port_stats->rtt_sum_ms += rtt;
		port_stats->last_rtt_ms = rtt;
		port_stats->tick_rtt_sum_ms += rtt;
		++port_stats->tick_rtt_count;
	}
	if (!measured)
		return;
	if (stats.rtt_samples == 0)
	{
		stats.rtt_min_ms = rtt;
		stats.rtt_max_ms = rtt;
	}
	else
	{
		stats.jitter_ms += (std::fabs(rtt - stats.last_rtt_ms) - stats.jitter_ms) / 16.0;
		stats.rtt_min_ms = std::min(stats.rtt_min_ms, rtt);
		stats.rtt_max_ms = std::max(stats.rtt_max_ms, rtt);
	}
	++stats.rtt_samples;
	stats.rtt_sum_ms += rtt;
	stats.last_rtt_ms = rtt;
	stats.tick_rtt_sum_ms += rtt;
	stats.tick_rtt_min_ms = stats.tick_rtt_count == 0 ? rtt : std::min(stats.tick_rtt_min_ms, rtt);
	stats.tick_rtt_max_ms = stats.tick_rtt_count == 0 ? rtt : std::max(stats.tick_rtt_max_ms, rtt);
	++stats.tick_rtt_count;
	++stats.rtt_hist[rtt_bucket(rtt)];
	stats.recent_rtt.push_back(rtt);
	if (stats.recent_rtt.size() > kRttWindow)
		stats.recent_rtt.pop_front();
}

#endif	// LAGSW_FEATURE_NET_MONITOR
