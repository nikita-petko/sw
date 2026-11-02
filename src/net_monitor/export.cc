// Export and logging of the net monitor: the measured window as CSV/JSON files and a continuous JSON Lines log.
#include "net_monitor.h"

#ifdef LAGSW_FEATURE_NET_MONITOR

#	include <algorithm>
#	include <cstdio>
#	include <ctime>
#	include <filesystem>
#	include <fstream>
#	include <sstream>

#	include "json.h"
#	include "log.h"

LOG_DEFAULT_GROUP(logging::group::backend)

namespace {
using Clock = std::chrono::steady_clock;

std::string number(double value)
{
	char text[32];
	std::snprintf(text, sizeof(text), "%.6g", value);
	return text;
}

std::string timestamp(const char* format)
{
	const std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	std::tm			  local{};
#	ifdef _WIN32
	localtime_s(&local, &now);
#	else
	localtime_r(&now, &local);
#	endif
	char text[40];
	std::strftime(text, sizeof(text), format, &local);
	return text;
}

std::string csv_quote(const std::string& text)
{
	std::string quoted = "\"";
	for (const char c : text)
		quoted += c == '"' ? std::string("\"\"") : std::string(1, c);
	return quoted + "\"";
}

double percentile(std::vector<double> samples, double fraction)
{
	if (samples.empty())
		return 0;
	std::sort(samples.begin(), samples.end());
	return samples[std::min(samples.size() - 1, static_cast<size_t>(fraction * static_cast<double>(samples.size())))];
}

const char* const kAlertNames[] = {"latency", "jitter", "retransmits", "stalls"};
const char* const kRttLabels[]	= {"<25ms", "25-49ms", "50-99ms", "100-199ms", "200-499ms", ">=500ms"};
const char* const kLevelNames[] = {"info", "alert", "ok"};
}  // namespace

std::string NetMonitor::export_snapshot_locked()
{
	namespace fs	   = std::filesystem;
	fs::path directory = options_.features.net_monitor.export_directory;
	if (directory.empty())
	{
		const std::string base = platform::data_directory();
		directory			   = base.empty() ? fs::path("netmonitor") : fs::path(base) / "netmonitor";
	}
	std::error_code error;
	fs::create_directories(directory, error);
	if (error)
		return "export failed: cannot create " + directory.string() + " (" + error.message() + ")";

	const std::string stem = "netmonitor-" + timestamp("%Y%m%d-%H%M%S");
	fs::path		  base = directory / stem;
	for (int attempt = 2; fs::exists(base.string() + ".csv", error) || fs::exists(base.string() + ".json", error); ++attempt)
		base = directory / (stem + "-" + std::to_string(attempt));

	// One row per server and second; the series of a server end at the same second, so they are aligned from their ends.
	std::ofstream csv(base.string() + ".csv");
	if (!csv)
		return "export failed: cannot write " + base.string() + ".csv";
	csv << "second,server,address,packets_down,packets_up,bytes_down,bytes_up,rtt_ms,rtt_min_ms,rtt_max_ms,retransmits,data_packets,new_"
		   "flows,score\n";
	const auto value_at = [](const Series& series, size_t from_end) -> std::string {
		return from_end < series.values.size() ? number(series.values[series.values.size() - 1 - from_end]) : std::string();
	};
	for (const std::string& address : server_order_)
	{
		const ServerStats& stats = servers_.at(address);
		const size_t	   rows	 = stats.pps_down.values.size();
		for (size_t row = 0; row < rows; ++row)
		{
			const size_t from_end = rows - 1 - row;
			csv << (elapsed_ticks_ - from_end) << ',' << csv_quote(stats.label) << ',' << address << ','
				<< value_at(stats.pps_down, from_end) << ',' << value_at(stats.pps_up, from_end) << ','
				<< value_at(stats.bps_down, from_end) << ',' << value_at(stats.bps_up, from_end) << ',' << value_at(stats.rtt, from_end)
				<< ',' << value_at(stats.rtt_min, from_end) << ',' << value_at(stats.rtt_max, from_end) << ','
				<< value_at(stats.retrans, from_end) << ',' << value_at(stats.data_pkts, from_end) << ','
				<< value_at(stats.flows_new, from_end) << ',' << value_at(stats.score, from_end) << '\n';
		}
	}
	csv.close();

	std::ofstream json(base.string() + ".json");
	if (!json)
		return "export failed: cannot write " + base.string() + ".json";
	const auto write_series = [&](const char* name, const Series& series) {
		json << "\"" << name << "\":[";
		for (size_t i = 0; i < series.values.size(); ++i)
			json << (i ? "," : "") << number(series.values[i]);
		json << "]";
	};
	json << "{\n \"generated\":\"" << timestamp("%Y-%m-%dT%H:%M:%S") << "\",\n \"elapsed_seconds\":" << elapsed_ticks_
		 << ",\n \"paused\":" << (paused_ ? "true" : "false") << ",\n \"capture\":{\"backend\":\""
		 << net_monitor_json::escape(backend::name()) << "\",\"description\":\"" << net_monitor_json::escape(capture_description_)
		 << "\",\"parsed\":" << total_packets_ << ",\"other\":" << other_packets_ << ",\"unparsed\":" << unparsed_packets_
		 << ",\"errors\":" << capture_errors_ << "},\n \"servers\":[";
	bool first_server = true;
	for (const std::string& address : server_order_)
	{
		const ServerStats&		  stats = servers_.at(address);
		const std::vector<double> window(stats.recent_rtt.begin(), stats.recent_rtt.end());
		json << (first_server ? "\n  " : ",\n  ") << "{\"address\":\"" << net_monitor_json::escape(address) << "\",\"label\":\""
			 << net_monitor_json::escape(stats.label) << "\",\"packets_up\":" << stats.up.packets
			 << ",\"packets_down\":" << stats.down.packets << ",\"bytes_up\":" << stats.up.bytes << ",\"bytes_down\":" << stats.down.bytes
			 << ",\"tcp_packets\":" << stats.tcp_packets << ",\"udp_packets\":" << stats.udp_packets << ",\"data_up\":" << stats.data_up
			 << ",\"data_down\":" << stats.data_down << ",\"retransmits_up\":" << stats.retrans_up
			 << ",\"retransmits_down\":" << stats.retrans_down << ",\"resets\":" << stats.resets << ",\"stalls\":" << stats.stalls
			 << ",\"handshakes\":" << stats.handshakes << ",\"flows_opened\":" << stats.flows_opened
			 << ",\n   \"rtt_ms\":{\"samples\":" << stats.rtt_samples << ",\"min\":" << number(stats.rtt_min_ms)
			 << ",\"avg\":" << number(stats.rtt_samples ? stats.rtt_sum_ms / static_cast<double>(stats.rtt_samples) : 0)
			 << ",\"p50\":" << number(percentile(window, 0.5)) << ",\"p95\":" << number(percentile(window, 0.95))
			 << ",\"max\":" << number(stats.rtt_max_ms) << ",\"jitter\":" << number(stats.jitter_ms)
			 << ",\"last\":" << number(stats.last_rtt_ms) << "},\n   \"rtt_histogram\":{";
		for (size_t i = 0; i < ServerStats::kRttBuckets; ++i)
			json << (i ? "," : "") << "\"" << kRttLabels[i] << "\":" << stats.rtt_hist[i];
		json << "},\n   \"alerts\":{";
		for (int kind = 0; kind < alert_kinds; ++kind)
			json << (kind ? "," : "") << "\"" << kAlertNames[kind] << "\":" << stats.alert_count[kind];
		json << "},\n   \"series\":{";
		write_series("packets_down", stats.pps_down);
		json << ",";
		write_series("packets_up", stats.pps_up);
		json << ",";
		write_series("bytes_down", stats.bps_down);
		json << ",";
		write_series("bytes_up", stats.bps_up);
		json << ",";
		write_series("rtt_ms", stats.rtt);
		json << ",";
		write_series("rtt_min_ms", stats.rtt_min);
		json << ",";
		write_series("rtt_max_ms", stats.rtt_max);
		json << ",";
		write_series("retransmits", stats.retrans);
		json << ",";
		write_series("score", stats.score);
		json << "}}";
		first_server = false;
	}
	json << "\n ],\n \"events\":[";
	for (size_t i = 0; i < events_.size(); ++i)
		json << (i ? ",\n  " : "\n  ") << "{\"second\":" << events_[i].tick << ",\"level\":\""
			 << kLevelNames[static_cast<int>(events_[i].level)] << "\",\"text\":\"" << net_monitor_json::escape(events_[i].text) << "\"}";
	json << "\n ],\n \"flows\":[";
	bool first_flow = true;
	for (const FlowRef& ref : sorted_flows_locked())
	{
		const Flow& flow = *ref.flow;
		json << (first_flow ? "\n  " : ",\n  ") << "{\"server\":\"" << net_monitor_json::escape(ref.address) << "\",\"protocol\":\""
			 << (flow.tcp ? "tcp" : "udp") << "\",\"client_port\":" << flow.client_port << ",\"server_port\":" << flow.server_port
			 << ",\"closed\":" << (flow.closed ? "true" : "false") << ",\"packets_up\":" << flow.packets_up
			 << ",\"packets_down\":" << flow.packets_down << ",\"bytes_up\":" << flow.bytes_up << ",\"bytes_down\":" << flow.bytes_down
			 << ",\"rtt_samples\":" << flow.rtt_samples
			 << ",\"rtt_avg_ms\":" << number(flow.rtt_samples ? flow.rtt_sum_ms / static_cast<double>(flow.rtt_samples) : 0) << "}";
		first_flow = false;
	}
	json << "\n ]\n}\n";
	json.close();
	if (!json)
		return "export failed: cannot write " + base.string() + ".json";
	return "exported to " + base.string() + ".csv/.json";
}

void NetMonitor::open_log()
{
	const std::string& path = options_.features.net_monitor.log_file;
	if (path.empty())
		return;
	namespace fs = std::filesystem;
	std::error_code error;
	const fs::path	parent = fs::path(path).parent_path();
	if (!parent.empty())
		fs::create_directories(parent, error);
	log_stream_.open(path, std::ios::app);
	std::lock_guard<std::mutex> lock(mutex_);
	if (!log_stream_)
	{
		status_message_ = "cannot write the log file " + path;
		status_until_	= Clock::now() + std::chrono::seconds(8);
		return;
	}
	log_stream_ << "{\"t\":0,\"event\":\"info\",\"text\":\"net monitor opened\",\"time\":\"" << timestamp("%Y-%m-%dT%H:%M:%S") << "\"}\n";
	log_stream_.flush();
}

void NetMonitor::close_log()
{
	if (!log_stream_.is_open())
		return;
	log_stream_ << "{\"t\":" << elapsed_ticks_ << ",\"event\":\"info\",\"text\":\"net monitor closed\",\"time\":\""
				<< timestamp("%Y-%m-%dT%H:%M:%S") << "\"}\n";
	log_stream_.close();
}

void NetMonitor::write_log_locked()
{
	if (!log_stream_.is_open())
		return;
	const auto		  last = [](const Series& series) { return series.values.empty() ? 0.0 : series.values.back(); };
	const std::string time = timestamp("%Y-%m-%dT%H:%M:%S");
	for (const std::string& address : server_order_)
	{
		const ServerStats& stats = servers_.at(address);
		log_stream_ << "{\"t\":" << elapsed_ticks_ << ",\"time\":\"" << time << "\",\"server\":\"" << net_monitor_json::escape(address)
					<< "\",\"packets_down\":" << number(last(stats.pps_down)) << ",\"packets_up\":" << number(last(stats.pps_up))
					<< ",\"bytes_down\":" << number(last(stats.bps_down)) << ",\"bytes_up\":" << number(last(stats.bps_up))
					<< ",\"rtt_ms\":" << number(last(stats.rtt)) << ",\"rtt_min_ms\":" << number(last(stats.rtt_min))
					<< ",\"rtt_max_ms\":" << number(last(stats.rtt_max)) << ",\"retransmits\":" << number(last(stats.retrans))
					<< ",\"new_flows\":" << number(last(stats.flows_new))
					<< ",\"score\":" << number(stats.score.values.empty() ? -1.0 : stats.score.values.back()) << "}\n";
	}
	log_stream_.flush();
}

#endif	// LAGSW_FEATURE_NET_MONITOR
