// Events, profile tracking and alerts of the net monitor.
#include "net_monitor.h"

#ifdef LAGSW_FEATURE_NET_MONITOR

#	include <algorithm>
#	include <cstdio>

#	include "internal.h"
#	include "json.h"
#	include "log.h"

LOG_DEFAULT_GROUP(logging::group::backend)

using namespace net_monitor_detail;

void NetMonitor::add_event_locked(Event::Level level, const std::string& text)
{
	events_.push_back({elapsed_ticks_, level, text});
	if (events_.size() > kMaxEvents)
		events_.pop_front();
	if (log_stream_.is_open())
	{
		const char* names[] = {"info", "alert", "ok"};
		log_stream_ << "{\"t\":" << elapsed_ticks_ << ",\"event\":\"" << names[static_cast<int>(level)] << "\",\"text\":\""
					<< net_monitor_json::escape(text) << "\"}\n";
		log_stream_.flush();
	}
}

void NetMonitor::track_profiles_locked(const Conditions& sample)
{
	size_t active = 0;
	profile_state_.resize(options_.profiles.size(), false);
	profile_stats_.resize(options_.profiles.size());
	for (size_t i = 0; i < profile_state_.size(); ++i)
	{
		const bool	  running = engine_.is_running(static_cast<int>(i) + 1);
		ProfileStats& stats	  = profile_stats_[i];
		active += running ? 1 : 0;
		if (running != profile_state_[i])
		{
			profile_state_[i] = running;
			if (running)
				++stats.activations;
			else
			{
				stats.last_ticks	= stats.current_ticks;
				stats.longest_ticks = std::max(stats.longest_ticks, stats.current_ticks);
				stats.current_ticks = 0;
			}
			add_event_locked(Event::Level::info, "profile '" + options_.profiles[i].name + "' " + (running ? "activated" : "deactivated"));
		}
		if (running)
		{
			++stats.current_ticks;
			stats.active.add(sample);
		}
	}
	if (active == 0)
		baseline_.add(sample);
	profile_active_.push(static_cast<double>(active));
}

void NetMonitor::raise_alert_locked(const std::string& label, ServerStats& stats, AlertKind kind, bool exceeded, const std::string& detail)
{
	static const char* const names[] = {"latency", "jitter", "retransmits", "stalls"};
	if (exceeded && !stats.alert_active[kind])
	{
		stats.alert_active[kind] = true;
		++stats.alert_count[kind];
		add_event_locked(Event::Level::alert, label + ": " + names[kind] + " " + detail);
	}
	else if (!exceeded && stats.alert_active[kind])
	{
		stats.alert_active[kind] = false;
		add_event_locked(Event::Level::ok, label + ": " + names[kind] + " back to normal");
	}
}

void NetMonitor::evaluate_alerts_locked(const std::string& label, ServerStats& stats)
{
	const NetMonitorOptions& limits = options_.features.net_monitor;
	char					 detail[96];

	// A threshold of 0 disables the alert; a second without samples keeps the state it had.
	if (limits.alert_rtt_ms == 0)
		raise_alert_locked(label, stats, alert_rtt, false, "");
	else if (stats.tick_rtt_count > 0)
	{
		const double rtt = stats.tick_rtt_sum_ms / stats.tick_rtt_count;
		std::snprintf(detail, sizeof(detail), "%.0f ms is above %u ms", rtt, limits.alert_rtt_ms);
		raise_alert_locked(label, stats, alert_rtt, rtt > limits.alert_rtt_ms, detail);
	}

	if (limits.alert_jitter_ms == 0)
		raise_alert_locked(label, stats, alert_jitter, false, "");
	else if (stats.rtt_samples > 0)
	{
		std::snprintf(detail, sizeof(detail), "%.0f ms is above %u ms", stats.jitter_ms, limits.alert_jitter_ms);
		raise_alert_locked(label, stats, alert_jitter, stats.jitter_ms > limits.alert_jitter_ms, detail);
	}

	if (limits.alert_retransmit_percent == 0)
		raise_alert_locked(label, stats, alert_retransmit, false, "");
	else
	{
		const size_t count		   = std::min(kRetransmitWindow, std::min(stats.retrans.values.size(), stats.data_pkts.values.size()));
		double		 retransmitted = 0, data = 0;
		for (size_t i = 0; i < count; ++i)
		{
			retransmitted += stats.retrans.values[stats.retrans.values.size() - 1 - i];
			data += stats.data_pkts.values[stats.data_pkts.values.size() - 1 - i];
		}
		if (data >= static_cast<double>(kMinAlertData))
		{
			const double percent = 100.0 * retransmitted / data;
			std::snprintf(detail,
						  sizeof(detail),
						  "%.1f%% in the last %zu s is above %u%%",
						  percent,
						  kRetransmitWindow,
						  limits.alert_retransmit_percent);
			raise_alert_locked(label, stats, alert_retransmit, percent > limits.alert_retransmit_percent, detail);
		}
	}

	if (limits.alert_stall_ms == 0)
		raise_alert_locked(label, stats, alert_stall, false, "");
	else
	{
		std::snprintf(detail,
					  sizeof(detail),
					  "no packet from the server for %.0f ms (limit %u ms)",
					  stats.tick_max_gap_ms,
					  limits.alert_stall_ms);
		raise_alert_locked(label, stats, alert_stall, stats.tick_max_gap_ms >= limits.alert_stall_ms, detail);
	}
}

void NetMonitor::log_alert_summary()
{
	static const char* const names[] = {"latency", "jitter", "retransmits", "stalls"};
	for (const std::string& address : server_order_)
	{
		const ServerStats& stats = servers_.at(address);
		std::string		   text;
		uint64_t		   total = 0;
		for (int kind = 0; kind < alert_kinds; ++kind)
		{
			total += stats.alert_count[kind];
			if (stats.alert_count[kind] > 0)
				text += std::string(text.empty() ? "" : ", ") + names[kind] + " x" + std::to_string(stats.alert_count[kind]);
		}
		if (total > 0)
			LOG_WARN("Net monitor: %s raised %llu alert(s) while the view was open (%s)",
					 stats.label.c_str(),
					 static_cast<unsigned long long>(total),
					 text.c_str());
	}
}

#endif	// LAGSW_FEATURE_NET_MONITOR
