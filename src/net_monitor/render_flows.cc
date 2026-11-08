// The per-flow screen of the net monitor.
#include "net_monitor.h"

#ifdef LAGSW_FEATURE_NET_MONITOR

#	include <algorithm>

#	include "internal.h"

using namespace net_monitor_detail;

std::string NetMonitor::render_flow_view(int console_columns, int console_rows)
{
	const size_t width		= static_cast<size_t>(console_columns > 0 ? std::max(console_columns, 60) : 100);
	const auto	 now		= paused_ ? paused_at_ : Clock::now();
	const size_t label_cols = std::clamp<size_t>(width / 8, 16, 24);
	const size_t value_cols = 13;
	const size_t chart_cols = std::min<size_t>(kHistory, width - label_cols - value_cols - 4);

	std::string out	 = "\033[H";
	auto		line = [&out](const std::string& text) { out += text + "\033[K\n"; };

	std::vector<std::string> warnings;
	out += render_header(width, warnings);
	line("");

	const std::vector<FlowRef> flows		  = sorted_flows_locked();
	size_t					   selected_index = flows.size();
	for (size_t i = 0; i < flows.size(); ++i)
		if (has_selection_ && flows[i].address == selection_.address && flows[i].key == selection_.key)
			selected_index = i;
	if (selected_index == flows.size() && !flows.empty())
		selected_index = 0;

	// Header, column titles, a blank line, the detail block (title, three charts, one line) and the footer stay; the rest is the list.
	const int	 fixed	   = 4 + static_cast<int>(warnings.size()) + 2 + 1 + 5 + 1;
	const size_t list_rows = console_rows > 0 ? static_cast<size_t>(std::max(3, console_rows - 1 - fixed)) : 20;
	const size_t first = flows.size() <= list_rows ? 0
												   : std::min(flows.size() - list_rows,
															  selected_index > list_rows / 2 ? selected_index - list_rows / 2 : size_t{0});

	const bool	 compact	= width < 97;
	const size_t name_cols	= std::clamp<size_t>(width > (compact ? 70 : 86) ? width - (compact ? 70 : 86) : 0, 10, 28);
	const size_t proto_cols = compact ? 4 : 6;
	const size_t port_cols	= compact ? 6 : 8;
	const size_t state_cols = compact ? 11 : 13;
	const size_t bytes_cols = compact ? 9 : 11;
	const size_t rtt_cols	= compact ? 7 : 9;
	const size_t idle_cols	= compact ? 7 : 9;
	line(std::string(kBold) + " Flows" + kReset + kDim + "  one row per connection (TCP) or port pair (UDP); Up/Down select" + kReset);
	line(std::string(kDim) + " " + pad("server", name_cols) + pad("proto", proto_cols) + pad_left("client", port_cols) +
		 pad_left("server", port_cols) + "  " + pad("state", state_cols) + pad_left("down", bytes_cols) + pad_left("up", bytes_cols) +
		 pad_left("RTT", rtt_cols) + pad_left("idle", idle_cols) + pad_left("duration", 8) + kReset);
	if (flows.empty())
		line(std::string(kDim) + " no flows seen yet" + kReset);
	for (size_t i = first; i < std::min(flows.size(), first + list_rows); ++i)
	{
		const Flow&	 flow	  = *flows[i].flow;
		const bool	 selected = i == selected_index;
		const double idle	  = elapsed_ms(flow.last_seen, now) / 1000.0;
		const double duration = elapsed_ms(flow.first_seen, flow.closed ? flow.closed_at : now) / 1000.0;
		std::string	 state;
		const char*	 color = kDim;
		if (!flow.tcp)
		{
			state = idle >= 5 ? "idle" : "active";
			color = idle >= 5 ? kDim : kCyan;
		}
		else if (flow.reset)
		{
			state = "reset";
			color = kRed;
		}
		else if (flow.closed)
			state = "closed";
		else if (flow.syn_pending)
		{
			state = "connecting";
			color = kYellow;
		}
		else if (flow.fin_out || flow.fin_in)
		{
			state = "closing";
			color = kYellow;
		}
		else
		{
			state = "established";
			color = kGreen;
		}
		line(std::string(selected ? kBold : "") + (selected ? ">" : " ") + pad(flows[i].stats->label, name_cols) +
			 pad(flow.tcp ? "tcp" : "udp", proto_cols) + pad_left(std::to_string(flow.client_port), port_cols) +
			 pad_left(std::to_string(flow.server_port), port_cols) + "  " + kReset + color + pad(state, state_cols) + kReset +
			 pad_left(format_size(static_cast<double>(flow.bytes_down)), bytes_cols) +
			 pad_left(format_size(static_cast<double>(flow.bytes_up)), bytes_cols) +
			 pad_left(format_ms(flow.last_rtt_ms, flow.rtt_samples > 0), rtt_cols) + pad_left(format_age(idle), idle_cols) +
			 pad_left(format_age(duration), 8));
	}
	line("");

	if (selected_index < flows.size())
	{
		const FlowRef& ref	= flows[selected_index];
		const Flow&	   flow = *ref.flow;
		line(std::string(kBold) + " Selected flow: " + kReset + ref.stats->label + " [" + ref.address + "]  " + (flow.tcp ? "tcp" : "udp") +
			 " port " + std::to_string(flow.client_port) + " -> " + std::to_string(flow.server_port));
		const auto chart = [&](const std::string& name, const std::string& value, const Series* series, double floor, const char* color) {
			line(" " + pad(name, label_cols) + pad_left(value, value_cols) + "  " +
				 (series ? sparkline(series->values, chart_cols, floor, color) : std::string(kDim) + "collecting..." + kReset));
		};
		const FlowDetail* detail = flow.detail.get();
		chart("down", detail ? format_rate(last_value(detail->bps_down.values)) : "-", detail ? &detail->bps_down : nullptr, 1024, kGreen);
		chart("up", detail ? format_rate(last_value(detail->bps_up.values)) : "-", detail ? &detail->bps_up : nullptr, 1024, kGreen);
		chart("latency (RTT)",
			  detail ? format_ms(last_value(detail->rtt.values), flow.rtt_samples > 0) : "-",
			  detail ? &detail->rtt : nullptr,
			  50,
			  rtt_color(flow.last_rtt_ms));
		const double average = flow.rtt_samples > 0 ? flow.rtt_sum_ms / static_cast<double>(flow.rtt_samples) : 0;
		line(" duration " + format_age(elapsed_ms(flow.first_seen, flow.closed ? flow.closed_at : now) / 1000.0) + "   packets " +
			 std::to_string(flow.packets_down) + " down / " + std::to_string(flow.packets_up) + " up   RTT last " +
			 format_ms(flow.last_rtt_ms, flow.rtt_samples > 0) + " avg " + format_ms(average, flow.rtt_samples > 0) + " (" +
			 std::to_string(flow.rtt_samples) + " samples)" +
			 (flow.tcp ? std::string("   retransmits are counted per server") : std::string("   no RTT for UDP")));
	}
	else
	{
		for (int i = 0; i < 5; ++i)
			line(i == 0 ? std::string(kDim) + " no flow selected" + kReset : "");
	}
	size_t active = 0;
	for (const FlowRef& ref : flows)
		active += ref.flow->closed ? 0 : 1;
	line(std::string(kDim) + " " + std::to_string(flows.size()) + " flow(s), " + std::to_string(active) + " not closed" + kReset);
	out += "\033[J";
	return out;
}

#endif	// LAGSW_FEATURE_NET_MONITOR
