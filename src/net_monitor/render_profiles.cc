// The per-profile screen of the net monitor.
#include "net_monitor.h"

#ifdef LAGSW_FEATURE_NET_MONITOR

#	include <algorithm>
#	include <cstdio>

#	include "internal.h"

using namespace net_monitor_detail;

std::string NetMonitor::render_profile_view(int console_columns, int console_rows)
{
	const size_t width = static_cast<size_t>(console_columns > 0 ? std::max(console_columns, 60) : 100);

	std::string out	 = "\033[H";
	auto		line = [&out](const std::string& text) { out += text + "\033[K\n"; };

	std::vector<std::string> warnings;
	out += render_header(width, warnings);
	line("");

	const size_t count = options_.profiles.size();
	// Header, two titles and column rows, the baseline row, two blank lines and the footer stay; the rest is shared by both tables.
	const int	 fixed = 4 + static_cast<int>(warnings.size()) + 9;
	const size_t shown = console_rows > 0 ? std::min(count, static_cast<size_t>(std::max(2, console_rows - 1 - fixed) / 2)) : count;

	const size_t name_cols	 = std::clamp<size_t>(width / 6, 10, 24);
	const size_t status_cols = width > name_cols + 60 ? width - name_cols - 60 : 0;

	line(std::string(kBold) + " Profile activity" + kReset + kDim + "  since the view opened or was reset" + kReset);
	line(std::string(kDim) + " " + pad("profile", name_cols) + pad("state", 9) + pad_left("runs", 6) + pad_left("active", 9) +
		 pad_left("share", 7) + pad_left("now", 9) + pad_left("last", 9) + pad_left("longest", 9) +
		 (status_cols > 0 ? "  " + pad("status", status_cols - 2) : std::string()) + kReset);
	if (count == 0)
		line(std::string(kDim) + " no profiles are configured" + kReset);
	for (size_t i = 0; i < shown; ++i)
	{
		const bool			running = i < profile_state_.size() && profile_state_[i];
		const ProfileStats	empty;
		const ProfileStats& stats	= i < profile_stats_.size() ? profile_stats_[i] : empty;
		const uint64_t		longest = std::max(stats.longest_ticks, stats.current_ticks);
		const std::string share	 = elapsed_ticks_ > 0
									   ? std::to_string(static_cast<int>(
											 100.0 * static_cast<double>(stats.active.ticks) / static_cast<double>(elapsed_ticks_) + 0.5)) +
											 "%"
									   : "-";
		const std::string status = running ? engine_.profile_packet_status(static_cast<int>(i) + 1) : std::string();
		line(" " + pad(options_.profiles[i].name, name_cols) + (running ? kGreen : kDim) + pad(running ? "active" : "idle", 9) + kReset +
			 pad_left(std::to_string(stats.activations), 6) + pad_left(format_age(static_cast<double>(stats.active.ticks)), 9) +
			 pad_left(share, 7) + pad_left(running ? format_age(static_cast<double>(stats.current_ticks)) : "-", 9) +
			 pad_left(stats.last_ticks > 0 ? format_age(static_cast<double>(stats.last_ticks)) : "-", 9) +
			 pad_left(longest > 0 ? format_age(static_cast<double>(longest)) : "-", 9) +
			 (status_cols > 0 ? "  " + std::string(kDim) + pad(status, status_cols - 2) + kReset : std::string()));
	}
	if (shown < count)
		line(std::string(kDim) + " ... " + std::to_string(count - shown) + " more profile(s) do not fit" + kReset);
	line("");

	line(std::string(kBold) + " Network while active" + kReset + kDim + "  compared with the seconds in which no profile was active" +
		 kReset);
	line(std::string(kDim) + " " + pad("profile", name_cols) + pad_left("time", 9) + pad_left("RTT", 10) + pad_left("vs idle", 10) +
		 pad_left("retrans", 9) + pad_left("down", 14) + kReset);
	const auto average_rtt = [](const Conditions& c) {
		return c.rtt_samples > 0 ? c.rtt_sum_ms / static_cast<double>(c.rtt_samples) : 0.0;
	};
	const auto row = [&](const std::string& name, const Conditions& c, bool compare) {
		char		text[24]	= "-";
		const char* delta_color = kDim;
		std::string delta		= "-";
		if (compare && c.rtt_samples > 0 && baseline_.rtt_samples > 0)
		{
			const double difference = average_rtt(c) - average_rtt(baseline_);
			delta					= format_ms_delta(difference);
			delta_color				= difference > 20 ? kRed : difference > 5 ? kYellow : kGreen;
		}
		const double loss = c.data_packets > 0 ? 100.0 * static_cast<double>(c.retransmits) / static_cast<double>(c.data_packets) : 0;
		if (c.data_packets > 0)
			std::snprintf(text, sizeof(text), "%.1f%%", loss);
		else
			std::snprintf(text, sizeof(text), "-");
		const std::string loss_text = text;
		line(" " + pad(name, name_cols) + pad_left(format_age(static_cast<double>(c.ticks)), 9) +
			 (c.rtt_samples > 0 ? rtt_color(average_rtt(c)) : kDim) + pad_left(format_ms(average_rtt(c), c.rtt_samples > 0), 10) + kReset +
			 delta_color + pad_left(delta, 10) + kReset + (c.data_packets > 0 ? loss_color(loss) : kDim) + pad_left(loss_text, 9) + kReset +
			 pad_left(c.ticks > 0 ? format_rate(static_cast<double>(c.bytes_down) / static_cast<double>(c.ticks)) : "-", 14));
	};
	row("no profile active", baseline_, false);
	for (size_t i = 0; i < shown; ++i)
		row(options_.profiles[i].name, i < profile_stats_.size() ? profile_stats_[i].active : Conditions{}, true);
	line("");
	line(std::string(kDim) + " A second counts for every profile that was active during it; profiles active together share their seconds." +
		 kReset);
	out += "\033[J";
	return out;
}

#endif	// LAGSW_FEATURE_NET_MONITOR
