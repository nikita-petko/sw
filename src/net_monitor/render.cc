// Render thread and the overview screen of the net monitor.
#include "net_monitor.h"

#ifdef LAGSW_FEATURE_NET_MONITOR

#	include <algorithm>
#	include <cstdio>

#	include "format.h"
#	include "internal.h"
#	include "log.h"
#	include "platform.h"

using namespace net_monitor_detail;

void NetMonitor::render_loop()
{
	int last_columns = -1, last_rows = -1;
	while (!stopping_)
	{
		// New servers need a new capture filter, which cannot be done while the capture thread needs the lock.
		refresh_servers();
		const int	columns	   = platform::console_width();
		const int	rows	   = platform::console_height();
		const int	frame_rows = rows - logging::pinned_status_rows(rows);
		std::string frame;
		{
			std::lock_guard<std::mutex> lock(mutex_);
			if (reset_requested_.exchange(false))
				reset_locked();
			if (!paused_ && Clock::now() - last_tick_ >= kTickInterval)
			{
				tick();
				last_tick_ += kTickInterval;
			}
			frame = view_ == View::flows	  ? render_flow_view(columns, frame_rows)
					: view_ == View::profiles ? render_profile_view(columns, frame_rows)
											  : render_frame(columns, frame_rows);
		}
		// A resized console reflows what is on it, so the screen is wiped instead of repainted over the old layout.
		if (columns != last_columns || rows != last_rows)
			frame.insert(0, "\033[2J");
		last_columns = columns;
		last_rows	 = rows;
		logging::write_frame(frame, rows);
		std::this_thread::sleep_for(kFrameInterval);
	}
}

std::string NetMonitor::render_header(size_t width, std::vector<std::string>& warnings)
{
	(void)width;
	const bool				 paused	   = paused_;
	const NetMonitorOptions& monitor   = options_.features.net_monitor;
	const std::string		 close_key = format_key(monitor.key);
	std::string				 out;
	const auto				 line = [&out](const std::string& text) { out += text + "\033[K\n"; };

	std::string status;
	if (!status_message_.empty() && Clock::now() < status_until_)
		status = std::string("  ") + kYellow + status_message_ + kReset;
	line(std::string(kBold) + " NETMONITOR " + kReset + (paused ? std::string(kYellow) + "[PAUSED]" : std::string(kGreen) + "[MEASURING]") +
		 kReset + "  " +
		 (view_ == View::flows		? "flows"
		  : view_ == View::profiles ? "profiles"
									: "overview") +
		 "  measured " + format_clock(elapsed_ticks_) + status);
	line(std::string(kDim) + " " + format_key(monitor.pause_key) + " pause | " + format_key(monitor.reset_key) + " reset | " +
		 format_key(monitor.flows_key) + " " + (view_ == View::flows ? "overview" : "flows") + " | " + format_key(monitor.profiles_key) +
		 " " + (view_ == View::profiles ? "overview" : "profiles") + " | " + format_key(monitor.export_key) + " export | " + close_key +
		 " close | q quit" + kReset);

	uint64_t packets_up = 0, packets_down = 0;
	for (const auto& entry : servers_)
	{
		packets_up += entry.second.up.packets;
		packets_down += entry.second.down.packets;
	}
	const std::string backend_text = std::string(backend::name()) + (capture_description_.empty() ? "" : " (" + capture_description_ + ")");
	line(std::string(kDim) + " capture " + backend_text + " | " + std::to_string(servers_.size()) + " server(s) | matched " +
		 std::to_string(packets_up + packets_down) + " | other " + std::to_string(other_packets_) + " | unparsed " +
		 std::to_string(unparsed_packets_) + " | errors " + std::to_string(capture_errors_) + kReset);

	warnings.clear();
	if (!open_error_.empty())
		warnings.push_back(std::string(kRed) + open_error_ + kReset);
	if (!paused && elapsed_ticks_ >= 5 && packets_up + packets_down == 0)
		warnings.push_back(
			std::string(kYellow) +
			"no packets from the configured servers were captured yet; check the servers and that the capture sees their traffic" + kReset);
	else if (!paused && elapsed_ticks_ >= 10 && packets_up == 0 && packets_down > 0)
		warnings.push_back(std::string(kYellow) +
						   "inbound packets are captured but no outbound ones; outbound traffic is not reaching the capture" + kReset);
	else if (!paused && elapsed_ticks_ >= 10 && packets_down == 0 && packets_up > 0)
		warnings.push_back(std::string(kYellow) +
						   "outbound packets are captured but no inbound ones; inbound traffic is not reaching the capture" + kReset);
	if (unparsed_packets_ >= 20 && unparsed_packets_ * 10 > total_packets_)
		warnings.push_back(std::string(kYellow) + "more than a tenth of the captured packets could not be parsed" + kReset);
	for (const std::string& warning : warnings)
		line(" ! " + warning);
	return out;
}

std::string NetMonitor::render_frame(int console_columns, int console_rows)
{
	const size_t width	= static_cast<size_t>(console_columns > 0 ? std::max(console_columns, 60) : 100);
	const bool	 paused = paused_;
	// While paused, silence is measured up to the moment of the pause.
	const auto	 now		= paused ? paused_at_ : Clock::now();
	const size_t label_cols = std::clamp<size_t>(width / 8, 16, 24);
	const size_t value_cols = 13;
	const size_t chart_cols = std::min<size_t>(kHistory, width - label_cols - value_cols - 4);

	std::string out	 = "\033[H";
	auto		line = [&out](const std::string& text) { out += text + "\033[K\n"; };

	std::vector<std::string> warnings;
	const std::string		 header		= render_header(width, warnings);
	uint64_t				 packets_up = 0, packets_down = 0, bytes_up = 0, bytes_down = 0, resets = 0, tcp = 0, udp = 0;
	for (const auto& entry : servers_)
	{
		const ServerStats& stats = entry.second;
		packets_up += stats.up.packets;
		packets_down += stats.down.packets;
		bytes_up += stats.up.bytes;
		bytes_down += stats.down.bytes;
		resets += stats.resets;
		tcp += stats.tcp_packets;
		udp += stats.udp_packets;
	}

	// The selected server's label contains its address in brackets unless the name equals the address.
	const std::string  selected = engine_.current_server();
	const ServerStats* focus	= nullptr;
	std::string		   focus_address;
	for (const std::string& address : server_order_)
	{
		if (selected == address || selected.find("[" + address + "]") != std::string::npos)
		{
			focus		  = &servers_.at(address);
			focus_address = address;
			break;
		}
	}

	// Spare terminal rows make every chart taller. The last row is left empty so the frame never scrolls.
	const size_t chart_count	= 6 + (focus ? 5 : 0) + 1 + 2;
	const size_t table_rows		= server_order_.size();
	size_t		 port_rows		= std::max<size_t>(1, std::min<size_t>(ports_.size(), 6));
	const int	 base_lines		= 4 + static_cast<int>(warnings.size()) + 1 + 6 + 2 + 1 + 1 + 1 + (focus ? 1 + 5 + 11 : 1) + 1 +
								  (1 + 1 + static_cast<int>(port_rows) + 1) + 4 + 4 + (1 + static_cast<int>(kEventRows) + 1) + 4 + 1 +
								  static_cast<int>(table_rows) + 1 + 1;
	const int	 spare			= console_rows > 0 ? console_rows - 1 - base_lines : 0;
	const size_t rows_per_chart = std::clamp<int>(1 + spare / static_cast<int>(chart_count), 1, 8);
	size_t		 table_limit	= table_rows;
	if (spare < 0)
	{
		// A short terminal gives up port rows first, then server rows.
		size_t		 deficit = static_cast<size_t>(-spare);
		const size_t cut	 = std::min(deficit, port_rows - 1);
		port_rows -= cut;
		deficit -= cut;
		table_limit = std::max<size_t>(1, table_rows > deficit ? table_rows - deficit : 1);
	}

	out += header;
	line("");

	auto chart = [&](const std::string& name, const std::string& value, const Series& series, double floor, const char* color) {
		const std::vector<std::string> rows = chart_rows(series.values, chart_cols, floor, color, rows_per_chart);
		for (size_t row = 0; row < rows.size(); ++row)
			line(" " + (row == 0 ? pad(name, label_cols) + pad_left(value, value_cols) : std::string(label_cols + value_cols, ' ')) + "  " +
				 rows[row]);
	};
	auto band_chart = [&](const std::string& name,
						  const std::string& value,
						  const Series&		 series,
						  const Series&		 low,
						  const Series&		 high,
						  double			 floor,
						  const char*		 color) {
		const std::vector<std::string> rows = band_rows(series.values, low.values, high.values, chart_cols, floor, color, rows_per_chart);
		for (size_t row = 0; row < rows.size(); ++row)
			line(" " + (row == 0 ? pad(name, label_cols) + pad_left(value, value_cols) : std::string(label_cols + value_cols, ' ')) + "  " +
				 rows[row]);
	};
	auto marker = [&](const std::string& name, const std::string& value, const Series& series, const char* color) {
		line(" " + pad(name, label_cols) + pad_left(value, value_cols) + "  " + marker_row(series.values, chart_cols, color));
	};
	auto half_open = [](const ServerStats& stats) {
		size_t count = 0;
		for (const auto& flow : stats.flows)
			count += flow.second.syn_pending ? 1 : 0;
		return count;
	};
	auto active_flows = [](const ServerStats& stats) {
		size_t count = 0;
		for (const auto& flow : stats.flows)
			count += flow.second.tcp && !flow.second.closed ? 1 : 0;
		return count;
	};
	auto count_text	 = [](double value) { return std::to_string(static_cast<uint64_t>(value)); };
	auto score_of	 = [](const ServerStats& stats) { return stats.score.values.empty() ? -1.0 : stats.score.values.back(); };
	auto score_arrow = [](const ServerStats& stats) {
		const auto& values = stats.score.values;
		if (values.size() < 11)
			return "►";
		const double change = values.back() - values[values.size() - 11];
		return change >= 5 ? "▲" : change <= -5 ? "▼" : "►";
	};

	line(std::string(kBold) + " All servers" + kReset);
	chart("packets/s down", count_text(last_value(total_.pps_down.values)), total_.pps_down, 10, kCyan);
	chart("packets/s up", count_text(last_value(total_.pps_up.values)), total_.pps_up, 10, kCyan);
	chart("bandwidth down", format_rate(last_value(total_.bps_down.values)), total_.bps_down, 1024, kGreen);
	chart("bandwidth up", format_rate(last_value(total_.bps_up.values)), total_.bps_up, 1024, kGreen);
	band_chart("latency (RTT)",
			   format_ms(total_.last_rtt_ms, total_.last_rtt_ms > 0),
			   total_.rtt,
			   total_.rtt_min,
			   total_.rtt_max,
			   50,
			   rtt_color(total_.last_rtt_ms));
	chart("retransmits/s", count_text(last_value(total_.retrans.values)), total_.retrans, 5, kRed);
	// These two rows share the time axis of the charts above: a mark means a profile was active, or an alert was raised, in that second.
	marker("profiles active",
		   std::to_string(static_cast<uint64_t>(last_value(profile_active_.values))) + "/" + std::to_string(options_.profiles.size()),
		   profile_active_,
		   "\033[35m");
	marker("alerts", std::to_string(static_cast<uint64_t>(last_value(alerts_active_.values))), alerts_active_, kRed);
	line(std::string(kDim) + " peak bandwidth  down " + format_rate(peak_bps_down_) + "   up " + format_rate(peak_bps_up_) + kReset);
	{
		char		 text[160];
		const double average = elapsed_ticks_ > 0 ? sum_pps_ / static_cast<double>(elapsed_ticks_) : 0;
		std::snprintf(text,
					  sizeof(text),
					  " burstiness  peak %.0f pkt/s vs average %.0f pkt/s (%.1fx)   up/down bytes %.2f",
					  peak_pps_,
					  average,
					  average > 0 ? peak_pps_ / average : 0.0,
					  bytes_down > 0 ? static_cast<double>(bytes_up) / static_cast<double>(bytes_down) : 0.0);
		line(std::string(kDim) + text + kReset);
	}
	line("");

	if (focus)
	{
		const std::vector<double> window(focus->recent_rtt.begin(), focus->recent_rtt.end());
		const bool				  has_rtt = focus->rtt_samples > 0;
		const double			  average = has_rtt ? focus->rtt_sum_ms / static_cast<double>(focus->rtt_samples) : 0;
		const double loss_up = 100.0 * static_cast<double>(focus->retrans_up) / static_cast<double>(std::max<uint64_t>(1, focus->data_up));
		const double loss_down =
			100.0 * static_cast<double>(focus->retrans_down) / static_cast<double>(std::max<uint64_t>(1, focus->data_down));
		const uint64_t packets = focus->up.packets + focus->down.packets;
		const uint64_t bytes   = focus->up.bytes + focus->down.bytes;

		line(std::string(kBold) + " Selected server: " + kReset + focus->label + " [" + focus_address + "]");
		band_chart("latency (RTT)",
				   format_ms(focus->last_rtt_ms, has_rtt),
				   focus->rtt,
				   focus->rtt_min,
				   focus->rtt_max,
				   50,
				   rtt_color(focus->last_rtt_ms));
		chart("packets/s down", count_text(last_value(focus->pps_down.values)), focus->pps_down, 10, kCyan);
		chart("packets/s up", count_text(last_value(focus->pps_up.values)), focus->pps_up, 10, kCyan);
		chart("retransmits/s", count_text(last_value(focus->retrans.values)), focus->retrans, 5, kRed);
		chart("new flows/s", count_text(last_value(focus->flows_new.values)), focus->flows_new, 2, kYellow);
		line(" RTT min/avg/p50/p95/max  " +
			 (has_rtt ? format_ms(focus->rtt_min_ms) + " / " + format_ms(average) + " / " + format_ms(percentile(window, 0.5)) + " / " +
							format_ms(percentile(window, 0.95)) + " / " + format_ms(focus->rtt_max_ms)
					  : std::string("no TCP round trip measured yet (UDP traffic has no RTT)")));
		{
			uint64_t samples = 0;
			for (const uint64_t count : focus->rtt_hist)
				samples += count;
			static const char* const blocks[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
			std::string				 spread	  = " RTT spread ";
			if (samples == 0)
				spread += std::string(kDim) + " no samples yet" + kReset;
			for (size_t i = 0; samples > 0 && i < ServerStats::kRttBuckets; ++i)
			{
				const double fraction = static_cast<double>(focus->rtt_hist[i]) / static_cast<double>(samples);
				char		 percent[16];
				std::snprintf(percent, sizeof(percent), "%.0f%%", fraction * 100);
				spread += std::string(" ") + kDim + kRttLabels[i] + " " + kReset + kCyan +
						  (focus->rtt_hist[i] > 0 ? blocks[std::min<size_t>(7, static_cast<size_t>(fraction * 7.999))] : " ") + kReset +
						  percent;
			}
			line(spread);
		}
		line(" RTT jitter " + format_ms(focus->jitter_ms, has_rtt) + "   arrival jitter " +
			 format_ms(focus->interarrival_jitter_ms, focus->has_in) + "   silence " +
			 (focus->has_in ? format_ms(elapsed_ms(focus->last_in, now)) : std::string("-")) + "   longest gap " +
			 format_ms(focus->max_gap_ms, focus->has_in));
		char loss[192];
		std::snprintf(loss,
					  sizeof(loss),
					  " retransmits  up %s%.2f%%%s (%llu)   down %s%.2f%%%s (%llu)   resets %llu",
					  loss_color(loss_up),
					  loss_up,
					  kReset,
					  static_cast<unsigned long long>(focus->retrans_up),
					  loss_color(loss_down),
					  loss_down,
					  kReset,
					  static_cast<unsigned long long>(focus->retrans_down),
					  static_cast<unsigned long long>(focus->resets));
		line(loss);
		char handshake[160];
		if (focus->handshakes > 0)
			std::snprintf(handshake,
						  sizeof(handshake),
						  " handshakes  %llu   last %s   avg %s   min %s   max %s   SYN retries %llu   half-open %zu",
						  static_cast<unsigned long long>(focus->handshakes),
						  format_ms(focus->last_handshake_ms).c_str(),
						  format_ms(focus->handshake_sum_ms / static_cast<double>(focus->handshakes)).c_str(),
						  format_ms(focus->handshake_min_ms).c_str(),
						  format_ms(focus->handshake_max_ms).c_str(),
						  static_cast<unsigned long long>(focus->syn_retries),
						  half_open(*focus));
		else
			std::snprintf(handshake,
						  sizeof(handshake),
						  " handshakes  none seen yet (open a new connection to measure)   SYN retries %llu   half-open %zu",
						  static_cast<unsigned long long>(focus->syn_retries),
						  half_open(*focus));
		line(handshake);
		line(" protocol  TCP " + std::to_string(focus->tcp_packets) + " | UDP " + std::to_string(focus->udp_packets) + "   avg packet " +
			 std::to_string(packets ? bytes / packets : 0) + " B   total " + std::to_string(packets) + " packets, " +
			 format_size(static_cast<double>(bytes)));
		line(" TCP health  duplicate ACKs up " + std::to_string(focus->dup_acks_up) + " / down " + std::to_string(focus->dup_acks_down) +
			 "   zero-window " + std::to_string(focus->zero_windows) + "   stalls (gap >= " + format_ms(kStallMs) + ") " +
			 std::to_string(focus->stalls));
		line(" TCP flags   SYN " + std::to_string(focus->syn_packets) + "  FIN " + std::to_string(focus->fin_packets) + "  RST " +
			 std::to_string(focus->resets) + "  PSH " + std::to_string(focus->psh_packets) + "  pure ACK " +
			 std::to_string(focus->pure_acks));
		const double minutes = elapsed_ticks_ > 0 ? static_cast<double>(elapsed_ticks_) / 60.0 : 0;
		char		 flows[160];
		std::snprintf(flows,
					  sizeof(flows),
					  " TCP flows   active %zu   opened %llu   churn %.1f/min (source port changes per minute)",
					  active_flows(*focus),
					  static_cast<unsigned long long>(focus->flows_opened),
					  static_cast<double>(focus->flows_opened) / std::max(minutes, 1.0 / 60));
		line(flows);
		if (focus->last_ttl >= 0)
		{
			const int hops = initial_ttl(focus->last_ttl) - focus->last_ttl;
			line(" path        TTL " + std::to_string(focus->last_ttl) + " (~" + std::to_string(hops) + " hops)   route changes " +
				 std::to_string(focus->ttl_changes) + "   DSCP " + std::to_string(focus->last_dscp) + " (" +
				 std::to_string(focus->dscp_changes) + " changes)   ECN-CE marks " + std::to_string(focus->ecn_marked));
		}
		else
			line(std::string(kDim) + " path        no inbound packet seen yet" + kReset);
		const double score = score_of(*focus);
		char		 score_text[64];
		std::snprintf(score_text, sizeof(score_text), "%.0f/100", score);
		line(std::string(" stability   ") +
			 (score >= 0 ? std::string(score_color(score)) + score_text + " " + score_arrow(*focus) + kReset : "-") + kDim +
			 "   (retransmits, jitter, stalls and resets since the view opened)" + kReset);
	}
	else
		line(std::string(kDim) + " No configured server is selected; showing all servers only." + kReset);
	line("");

	// Ports: the server-side port of each flow, busiest first.
	std::vector<const PortStats*> ranked;
	for (const auto& entry : ports_)
		ranked.push_back(&entry.second);
	std::sort(ranked.begin(), ranked.end(), [](const PortStats* a, const PortStats* b) {
		return a->up.packets + a->down.packets > b->up.packets + b->down.packets;
	});
	const size_t port_trend = width > 96 ? std::min<size_t>(kHistory, width - 96) : 0;
	line(std::string(kBold) + " Ports (server side, top " + std::to_string(port_rows) + " of " + std::to_string(ports_.size()) + ")" +
		 kReset);
	line(std::string(kDim) + " " + pad("port", 22) + pad_left("pkt/s v", 9) + pad_left("pkt/s ^", 9) + pad_left("rate v", 14) +
		 pad_left("rate ^", 14) + pad_left("RTT", 10) + "  trend" + kReset);
	if (ranked.empty())
		line(std::string(kDim) + " no traffic seen yet" + kReset);
	for (size_t i = 0; i < std::min(port_rows, ranked.size()); ++i)
	{
		const PortStats&  port	  = *ranked[i];
		const std::string service = service_name(port.port);
		const bool		  has_rtt = port.rtt_samples > 0;
		line(" " + pad(std::string(port.tcp ? "tcp/" : "udp/") + std::to_string(port.port) + (service.empty() ? "" : " " + service), 22) +
			 pad_left(count_text(port.pkts_down), 9) + pad_left(count_text(port.pkts_up), 9) + pad_left(format_rate(port.rate_down), 14) +
			 pad_left(format_rate(port.rate_up), 14) + (has_rtt ? rtt_color(port.last_rtt_ms) : kDim) +
			 pad_left(format_ms(port.last_rtt_ms, has_rtt), 10) + kReset + "  " + sparkline(port.pps.values, port_trend, 10, kCyan));
	}
	line("");

	line(std::string(kBold) + " Packet sizes" + kReset);
	for (int direction = 0; direction < 2; ++direction)
	{
		const uint64_t* buckets = direction == 0 ? size_down_ : size_up_;
		uint64_t		sum		= 0;
		for (size_t i = 0; i < kSizeBuckets; ++i)
			sum += buckets[i];
		std::string	 text = std::string(" ") + (direction == 0 ? "down  " : "up    ");
		const size_t bar_cols =
			static_cast<size_t>(std::clamp<int>((static_cast<int>(width) - 8) / static_cast<int>(kSizeBuckets) - 18, 4, 40));
		for (size_t i = 0; i < kSizeBuckets; ++i)
		{
			const double fraction = sum ? static_cast<double>(buckets[i]) / static_cast<double>(sum) : 0;
			char		 percent[16];
			std::snprintf(percent, sizeof(percent), "%3.0f%%", fraction * 100);
			text += std::string(kDim) + pad(kSizeLabels[i], 11) + kReset + kCyan + bar(fraction, bar_cols) + kReset + " " + percent + "  ";
		}
		line(text);
	}
	line("");

	line(std::string(kBold) + " lagsw effect" + kReset);
	{
		size_t active = 0;
		for (size_t i = 0; i < options_.profiles.size(); ++i)
			active += engine_.is_running(static_cast<int>(i) + 1) ? 1 : 0;
		chart("packets queued", std::to_string(static_cast<uint64_t>(last_value(queued_.values))), queued_, 4, kYellow);
		std::string info = " profiles active " + std::to_string(active) + "/" + std::to_string(options_.profiles.size()) +
						   "   queue peak " + std::to_string(peak_queued_) + "   next release in " +
						   format_ms(static_cast<double>(engine_.next_batch_in_ms()));
#	ifdef LAGSW_FEATURE_PASSIVE_LATENCY
		if (engine_.is_passive_latency_enabled())
			info += "   passive latency " + engine_.passive_latency_status() + (engine_.is_passive_latency_paused() ? " [paused]" : "");
#	endif
		line(info);
	}
	line("");

	line(std::string(kBold) + " Events" + kReset + kDim + "  (profile activations, alerts, discovered servers)" + kReset);
	{
		const size_t shown_events = std::min(kEventRows, events_.size());
		const size_t text_cols	  = width > 16 ? width - 16 : 1;
		for (size_t i = 0; i < kEventRows; ++i)
		{
			if (i >= shown_events)
			{
				line(i == 0 ? std::string(kDim) + " no events yet" + kReset : "");
				continue;
			}
			const Event& event = events_[events_.size() - shown_events + i];
			const char*	 color = event.level == Event::Level::alert ? kRed : event.level == Event::Level::ok ? kGreen : kCyan;
			line(std::string(kDim) + " [" + format_clock(event.tick) + "] " + kReset + color + pad(event.text, text_cols) + kReset);
		}
	}
	line("");

	line(std::string(kBold) + " This machine" + kReset);
	{
		char cpu[24];
		std::snprintf(cpu, sizeof(cpu), "%.1f%%", last_value(cpu_.values));
		chart("lagsw CPU", system_prev_.cpu_available ? cpu : "n/a", cpu_, 10, kGreen);
		chart("NIC errors+drops/s",
			  system_prev_.nic_available ? count_text(last_value(nic_problems_.values)) : "n/a",
			  nic_problems_,
			  5,
			  kRed);
	}
	line("");

	const size_t name_cols	= std::clamp<size_t>(width / 5, 14, 40);
	const size_t trend_cols = std::min<size_t>(kHistory, width > name_cols + 75 ? width - name_cols - 75 : 0);
	line(std::string(kBold) + " " + pad("Server", name_cols) + pad_left("pkt/s v", 9) + pad_left("pkt/s ^", 9) + pad_left("RTT", 10) +
		 pad_left("avg", 10) + pad_left("jitter", 9) + pad_left("retx%", 8) + pad_left("silent", 9) + pad_left("score", 7) + "  RTT trend" +
		 kReset);
	// The authoritative server leads the table; the others follow by average packets per second over the charted window.
	const auto average_usage = [](const ServerStats& stats) {
		const size_t samples = std::min(stats.pps_up.values.size(), stats.pps_down.values.size());
		if (samples == 0)
			return 0.0;
		double sum = 0;
		for (size_t i = 0; i < samples; ++i)
			sum += stats.pps_up.values[stats.pps_up.values.size() - samples + i] +
				   stats.pps_down.values[stats.pps_down.values.size() - samples + i];
		return sum / static_cast<double>(samples);
	};
#	ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	const bool focus_authoritative = engine_.is_authoritative_server();
#	else
	const bool focus_authoritative = false;
#	endif
	std::vector<std::string> table_order = server_order_;
	std::stable_sort(table_order.begin(), table_order.end(), [&](const std::string& a, const std::string& b) {
		const bool a_leads = focus_authoritative && a == focus_address;
		const bool b_leads = focus_authoritative && b == focus_address;
		if (a_leads != b_leads)
			return a_leads;
		return average_usage(servers_.at(a)) > average_usage(servers_.at(b));
	});
	size_t shown = 0;
	for (const std::string& address : table_order)
	{
		if (shown++ >= table_limit)
			break;
		const ServerStats& stats   = servers_.at(address);
		const bool		   seen	   = stats.up.packets + stats.down.packets > 0;
		const double	   data	   = static_cast<double>(stats.data_up + stats.data_down);
		const double	   retx	   = data > 0 ? 100.0 * static_cast<double>(stats.retrans_up + stats.retrans_down) / data : 0;
		const bool		   has_rtt = stats.rtt_samples > 0;
		const double	   average = has_rtt ? stats.rtt_sum_ms / static_cast<double>(stats.rtt_samples) : 0;
		const bool		   current = &stats == focus;
		const double	   score   = score_of(stats);
		char			   retx_text[16], score_text[16];
		std::snprintf(retx_text, sizeof(retx_text), "%.1f", retx);
		std::snprintf(score_text, sizeof(score_text), "%.0f", score);
		bool alerting = false;
		for (const bool active : stats.alert_active)
			alerting = alerting || active;
		line(std::string(alerting  ? kRed
						 : current ? kBold
								   : "") +
			 (alerting	? "!"
			  : current ? ">"
						: " ") +
			 pad(stats.label, name_cols) + kReset + pad_left(seen ? count_text(last_value(stats.pps_down.values)) : "-", 9) +
			 pad_left(seen ? count_text(last_value(stats.pps_up.values)) : "-", 9) + (has_rtt ? rtt_color(stats.last_rtt_ms) : kDim) +
			 pad_left(format_ms(stats.last_rtt_ms, has_rtt), 10) + kReset + pad_left(format_ms(average, has_rtt), 10) +
			 pad_left(format_ms(stats.jitter_ms, has_rtt), 9) + (data > 0 ? loss_color(retx) : kDim) +
			 pad_left(data > 0 ? retx_text : "-", 8) + kReset +
			 pad_left(stats.has_in ? format_ms(elapsed_ms(stats.last_in, now)) : "-", 9) + (score >= 0 ? score_color(score) : kDim) +
			 pad_left(score >= 0 ? score_text : "-", 7) + kReset + "  " +
			 sparkline(stats.rtt.values, trend_cols, 50, has_rtt ? rtt_color(stats.last_rtt_ms) : kDim));
	}
	line("");
	line(std::string(kDim) + " Totals: " + std::to_string(packets_down) + " down / " + std::to_string(packets_up) + " up packets, " +
		 format_size(static_cast<double>(bytes_down)) + " down / " + format_size(static_cast<double>(bytes_up)) + " up, TCP " +
		 std::to_string(tcp) + " / UDP " + std::to_string(udp) + ", resets " + std::to_string(resets) + kReset);
	out += "\033[J";
	return out;
}

#endif	// LAGSW_FEATURE_NET_MONITOR
