// Once-a-second tick of the net monitor: turns the counters into rates, history and the log.
#include "net_monitor.h"

#ifdef LAGSW_FEATURE_NET_MONITOR

#	include <algorithm>

#	include "internal.h"
#	include "platform.h"

using namespace net_monitor_detail;

void NetMonitor::tick()
{
	// Events raised during this second carry its number.
	++elapsed_ticks_;
	double	 rtt_sum   = 0;
	uint32_t rtt_count = 0;
	double	 total_rtt = total_.last_rtt_ms;
	uint64_t retrans   = 0;
	uint64_t data_tick = 0;
	uint64_t flows_new = 0;
	double	 pps_up = 0, pps_down = 0, bps_up = 0, bps_down = 0;
	double	 band_min = 0, band_max = 0;
	size_t	 active_alerts = 0;
	for (auto& entry : servers_)
	{
		ServerStats& stats = entry.second;
		stats.pps_up.push(static_cast<double>(stats.up.packets_tick));
		stats.pps_down.push(static_cast<double>(stats.down.packets_tick));
		stats.bps_up.push(static_cast<double>(stats.up.bytes_tick));
		stats.bps_down.push(static_cast<double>(stats.down.bytes_tick));
		stats.flows_new.push(static_cast<double>(stats.flows_tick));
		flows_new += stats.flows_tick;
		stats.flows_tick = 0;
		if (stats.tick_rtt_count > 0)
		{
			stats.rtt.push(stats.tick_rtt_sum_ms / stats.tick_rtt_count);
			stats.rtt_min.push(stats.tick_rtt_min_ms);
			stats.rtt_max.push(stats.tick_rtt_max_ms);
			band_min = rtt_count > 0 ? std::min(band_min, stats.tick_rtt_min_ms) : stats.tick_rtt_min_ms;
			band_max = rtt_count > 0 ? std::max(band_max, stats.tick_rtt_max_ms) : stats.tick_rtt_max_ms;
			rtt_sum += stats.tick_rtt_sum_ms;
			rtt_count += stats.tick_rtt_count;
		}
		else
		{
			stats.rtt.push(last_value(stats.rtt.values));
			stats.rtt_min.push(last_value(stats.rtt_min.values));
			stats.rtt_max.push(last_value(stats.rtt_max.values));
		}
		const uint64_t retrans_now = stats.retrans_up + stats.retrans_down;
		stats.retrans.push(static_cast<double>(retrans_now - stats.retrans_prev));
		retrans += retrans_now - stats.retrans_prev;
		stats.retrans_prev		= retrans_now;
		const uint64_t data_now = stats.data_up + stats.data_down;
		stats.data_pkts.push(static_cast<double>(data_now - stats.data_prev));
		data_tick += data_now - stats.data_prev;
		stats.data_prev = data_now;
		if (stats.up.packets + stats.down.packets > 0)
		{
			const double data = static_cast<double>(stats.data_up + stats.data_down);
			stats.score.push(stability_score(data > 0 ? 100.0 * static_cast<double>(retrans_now) / data : 0,
											 stats.jitter_ms,
											 stats.interarrival_jitter_ms,
											 stats.resets,
											 stats.stalls));
		}
		evaluate_alerts_locked(stats.label, stats);
		for (const bool active : stats.alert_active)
			active_alerts += active ? 1 : 0;
		for (auto& flow_entry : stats.flows)
		{
			Flow& flow = flow_entry.second;
			if (has_selection_ && selection_.key == flow_entry.first && selection_.address == entry.first && !flow.detail)
				flow.detail = std::make_shared<FlowDetail>();
			if (flow.detail)
			{
				flow.detail->bps_down.push(static_cast<double>(flow.bytes_down_tick));
				flow.detail->bps_up.push(static_cast<double>(flow.bytes_up_tick));
				flow.detail->rtt.push(flow.rtt_tick_count > 0 ? flow.rtt_tick_sum_ms / flow.rtt_tick_count
															  : last_value(flow.detail->rtt.values));
			}
			flow.bytes_down_tick = flow.bytes_up_tick = 0;
			flow.rtt_tick_sum_ms					  = 0;
			flow.rtt_tick_count						  = 0;
		}
		pps_up += static_cast<double>(stats.up.packets_tick);
		pps_down += static_cast<double>(stats.down.packets_tick);
		bps_up += static_cast<double>(stats.up.bytes_tick);
		bps_down += static_cast<double>(stats.down.bytes_tick);
		stats.up.packets_tick = stats.down.packets_tick = 0;
		stats.up.bytes_tick = stats.down.bytes_tick = 0;
		stats.tick_rtt_sum_ms						= 0;
		stats.tick_rtt_count						= 0;
		stats.tick_max_gap_ms						= 0;
	}
	for (auto& entry : ports_)
	{
		PortStats& port = entry.second;
		port.pps.push(static_cast<double>(port.up.packets_tick + port.down.packets_tick));
		if (port.tick_rtt_count > 0)
			port.rtt.push(port.tick_rtt_sum_ms / port.tick_rtt_count);
		else
			port.rtt.push(last_value(port.rtt.values));
		port.pkts_up		 = static_cast<double>(port.up.packets_tick);
		port.pkts_down		 = static_cast<double>(port.down.packets_tick);
		port.rate_up		 = static_cast<double>(port.up.bytes_tick);
		port.rate_down		 = static_cast<double>(port.down.bytes_tick);
		port.up.packets_tick = port.down.packets_tick = 0;
		port.up.bytes_tick = port.down.bytes_tick = 0;
		port.tick_rtt_sum_ms					  = 0;
		port.tick_rtt_count						  = 0;
	}
	peak_bps_up_   = std::max(peak_bps_up_, bps_up);
	peak_bps_down_ = std::max(peak_bps_down_, bps_down);
	peak_pps_	   = std::max(peak_pps_, pps_up + pps_down);
	sum_pps_ += pps_up + pps_down;
	const uint64_t queued = engine_.pending_packets();
	queued_.push(static_cast<double>(queued));
	peak_queued_ = std::max(peak_queued_, queued);

	const platform::SystemCounters system = platform::system_counters();
	if (system_has_prev_)
	{
		cpu_.push(system.cpu_available ? 100.0 * std::max(0.0, system.cpu_seconds - system_prev_.cpu_seconds) : 0);
		// An interface that goes down drops out of the sum, so the counter can move backwards.
		const uint64_t problems_now	 = system.nic_errors + system.nic_drops;
		const uint64_t problems_prev = system_prev_.nic_errors + system_prev_.nic_drops;
		nic_problems_.push(system.nic_available && problems_now >= problems_prev ? static_cast<double>(problems_now - problems_prev) : 0);
	}
	system_prev_	 = system;
	system_has_prev_ = true;

	if (rtt_count > 0)
	{
		total_rtt = rtt_sum / rtt_count;
		total_.rtt_min.push(band_min);
		total_.rtt_max.push(band_max);
	}
	else
	{
		total_.rtt_min.push(last_value(total_.rtt_min.values));
		total_.rtt_max.push(last_value(total_.rtt_max.values));
	}
	total_.last_rtt_ms = total_rtt;
	total_.pps_up.push(pps_up);
	total_.pps_down.push(pps_down);
	total_.bps_up.push(bps_up);
	total_.bps_down.push(bps_down);
	total_.rtt.push(total_rtt);
	total_.retrans.push(static_cast<double>(retrans));
	total_.flows_new.push(static_cast<double>(flows_new));
	// The selected flow can have been evicted; the view then falls back to the first one.
	if (has_selection_)
	{
		const auto selected_server = servers_.find(selection_.address);
		if (selected_server == servers_.end() || !selected_server->second.flows.count(selection_.key))
			has_selection_ = false;
	}
	if (view_ == View::flows && !has_selection_)
		move_flow_selection_locked(0);
	Conditions sample;
	sample.ticks		= 1;
	sample.rtt_sum_ms	= rtt_sum;
	sample.rtt_samples	= rtt_count;
	sample.data_packets = data_tick;
	sample.retransmits	= retrans;
	sample.bytes_down	= static_cast<uint64_t>(bps_down);
	track_profiles_locked(sample);
	alerts_active_.push(static_cast<double>(active_alerts));
	write_log_locked();
}

#endif	// LAGSW_FEATURE_NET_MONITOR
