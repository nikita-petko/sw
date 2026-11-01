#include "net_monitor.h"

#ifdef LAGSW_FEATURE_NET_MONITOR

#include <algorithm>
#include <cmath>
#include <cstdio>

#include "format.h"
#include "log.h"
#include "packet_engine_util.h"
#include "packet_headers.h"
#include "platform.h"

LOG_DEFAULT_GROUP(logging::group::backend)

namespace {
using Clock = std::chrono::steady_clock;

constexpr size_t kHistory			= 600;	// seconds of history kept; wide terminals show as much as fits
constexpr size_t kRttWindow			= 256;	// RTT samples used for the percentiles
constexpr size_t kPendingPerFlow	= 128;
constexpr size_t kMaxFlowsPerServer = 256;
constexpr size_t kMaxPorts			= 64;
constexpr double kStallMs			= 250;	// an inbound gap at least this long counts as a stall
constexpr auto	 kTickInterval		= std::chrono::seconds(1);
constexpr auto	 kFrameInterval		= std::chrono::milliseconds(200);

const char* const kReset  = "\033[0m";
const char* const kDim	  = "\033[90m";
const char* const kBold	  = "\033[1m";
const char* const kGreen  = "\033[32m";
const char* const kYellow = "\033[33m";
const char* const kRed	  = "\033[31m";
const char* const kCyan	  = "\033[36m";

/// Sequence-number comparison that survives wraparound.
bool seq_gt(uint32_t a, uint32_t b)
{
	return static_cast<int32_t>(a - b) > 0;
}

double elapsed_ms(Clock::time_point from, Clock::time_point to)
{
	return std::chrono::duration<double, std::milli>(to - from).count();
}

/// Bytes of transport payload in an IP packet, or 0 when it cannot be determined.
uint32_t payload_length(const ParsedPacket& parsed, uint32_t captured_length)
{
	uint32_t ip_header = 0;
	uint32_t total	   = 0;
	if (parsed.ipv4)
	{
		total	  = swap_u16(parsed.ipv4->Length);
		ip_header = static_cast<uint32_t>(parsed.ipv4->HdrLength) * 4;
	}
	else if (parsed.ipv6)
	{
		total	  = static_cast<uint32_t>(swap_u16(parsed.ipv6->Length)) + 40;
		ip_header = 40;
	}
	else
		return 0;
	// Large send offload leaves the length field zero; fall back to the captured size.
	if (total <= ip_header)
		total = captured_length;
	uint32_t header_bytes = ip_header;
	if (parsed.tcp)
		header_bytes += static_cast<uint32_t>(parsed.tcp->HdrLength) * 4;
	else if (parsed.udp)
		header_bytes += 8;
	else
		return 0;
	return total > header_bytes ? total - header_bytes : 0;
}

const char* rtt_color(double rtt_ms)
{
	return rtt_ms < 60 ? kGreen : rtt_ms < 120 ? kYellow : kRed;
}

const char* loss_color(double percent)
{
	return percent < 0.5 ? kGreen : percent < 2 ? kYellow : kRed;
}

const char* score_color(double score)
{
	return score >= 85 ? kGreen : score >= 60 ? kYellow : kRed;
}

std::string format_size(double bytes)
{
	char text[32];
	if (bytes >= 1024 * 1024)
		std::snprintf(text, sizeof(text), "%.2f MB", bytes / (1024 * 1024));
	else if (bytes >= 1024)
		std::snprintf(text, sizeof(text), "%.1f KB", bytes / 1024);
	else
		std::snprintf(text, sizeof(text), "%.0f B", bytes);
	return text;
}

std::string format_rate(double bytes_per_second)
{
	const double bits = bytes_per_second * 8;
	char		 text[32];
	if (bits >= 1e9)
		std::snprintf(text, sizeof(text), "%.2f Gbit/s", bits / 1e9);
	else if (bits >= 1e6)
		std::snprintf(text, sizeof(text), "%.2f Mbit/s", bits / 1e6);
	else if (bits >= 1e3)
		std::snprintf(text, sizeof(text), "%.1f kbit/s", bits / 1e3);
	else
		std::snprintf(text, sizeof(text), "%.0f bit/s", bits);
	return text;
}

const char* service_name(uint16_t port)
{
	switch (port)
	{
		case 53: return "dns";
		case 80: return "http";
		case 443: return "https/quic";
		case 3074: return "xbox live";
		case 3478: return "stun";
		case 3479: return "turn";
		case 3480: return "turn";
		case 3544: return "teredo";
		case 4380: return "steam";
		case 5222: return "xmpp";
		case 9308: return "playstation";
		case 27015: return "source";
		default: return "";
	}
}

constexpr uint32_t kSizeLimits[] = {128, 512, 1024};
const char* const  kSizeLabels[] = {"<128 B", "128-511 B", "512-1023 B", ">=1024 B"};

size_t size_bucket(uint32_t length)
{
	size_t bucket = 0;
	while (bucket < 3 && length >= kSizeLimits[bucket])
		++bucket;
	return bucket;
}

std::string bar(double fraction, size_t width)
{
	const size_t filled = std::min(width, static_cast<size_t>(fraction * static_cast<double>(width) + 0.5));
	std::string	 out;
	for (size_t i = 0; i < width; ++i)
		out += i < filled ? "█" : "░";
	return out;
}

std::string format_ms(double value, bool available = true)
{
	if (!available)
		return "-";
	char text[24];
	std::snprintf(text, sizeof(text), value < 10 ? "%.1f ms" : "%.0f ms", value);
	return text;
}

std::string format_clock(uint64_t seconds)
{
	char text[24];
	std::snprintf(text, sizeof(text), "%02llu:%02llu:%02llu", static_cast<unsigned long long>(seconds / 3600),
				  static_cast<unsigned long long>(seconds / 60 % 60), static_cast<unsigned long long>(seconds % 60));
	return text;
}

std::string pad(const std::string& text, size_t width)
{
	if (text.size() >= width)
		return text.substr(0, width);
	return text + std::string(width - text.size(), ' ');
}

std::string pad_left(const std::string& text, size_t width)
{
	return text.size() >= width ? text : std::string(width - text.size(), ' ') + text;
}

/// Renders the last `width` values as a block-character chart. The scale starts at zero and ends at the
/// window maximum (at least `floor`, so an idle line does not look busy).
std::string sparkline(const std::deque<double>& values, size_t width, double floor, const char* color)
{
	static const char* const blocks[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
	const size_t			 count	  = std::min(width, values.size());
	double					 top	  = floor;
	for (size_t i = values.size() - count; i < values.size(); ++i)
		top = std::max(top, values[i]);
	std::string line = std::string(color);
	line.append(width - count, ' ');
	for (size_t i = values.size() - count; i < values.size(); ++i)
	{
		const double ratio = top > 0 ? values[i] / top : 0;
		line += values[i] <= 0 ? " " : blocks[std::min<size_t>(7, static_cast<size_t>(ratio * 7.999))];
	}
	return line + kReset;
}

/// A multi-row variant of sparkline(): the value range is split over `rows` * 8 levels, top row first.
std::vector<std::string> chart_rows(const std::deque<double>& values, size_t width, double floor, const char* color, size_t rows)
{
	if (rows <= 1)
		return {sparkline(values, width, floor, color)};
	static const char* const blocks[] = {" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
	const size_t			 count	  = std::min(width, values.size());
	double					 top	  = floor;
	for (size_t i = values.size() - count; i < values.size(); ++i)
		top = std::max(top, values[i]);
	std::vector<std::string> lines(rows, std::string(color));
	for (std::string& line : lines)
		line.append(width - count, ' ');
	for (size_t i = values.size() - count; i < values.size(); ++i)
	{
		const size_t levels = values[i] <= 0 ? 0 : std::max<size_t>(1, static_cast<size_t>(values[i] / top * static_cast<double>(rows * 8) + 0.5));
		for (size_t row = 0; row < rows; ++row)
		{
			const size_t from = (rows - 1 - row) * 8;
			lines[row] += blocks[levels <= from ? 0 : std::min<size_t>(8, levels - from)];
		}
	}
	for (std::string& line : lines)
		line += kReset;
	return lines;
}

double percentile(std::vector<double> samples, double fraction)
{
	if (samples.empty())
		return 0;
	std::sort(samples.begin(), samples.end());
	return samples[std::min(samples.size() - 1, static_cast<size_t>(fraction * static_cast<double>(samples.size())))];
}

double last_value(const std::deque<double>& values)
{
	return values.empty() ? 0.0 : values.back();
}

/// The initial TTL a sender most likely used (the next common default at or above the observed value).
int initial_ttl(int observed)
{
	for (const int initial : {32, 64, 128, 255})
		if (observed <= initial)
			return initial;
	return 255;
}

/// Link quality from 0 to 100, based on everything measured since the view was opened. -1 when nothing was seen.
double stability_score(double retransmit_percent, double jitter_ms, double arrival_jitter_ms, uint64_t resets, uint64_t stalls)
{
	const double penalty = std::min(40.0, retransmit_percent * 8) + std::min(25.0, jitter_ms / 2) + std::min(15.0, arrival_jitter_ms / 5) +
						   std::min(10.0, static_cast<double>(resets) * 2) + std::min(10.0, static_cast<double>(stalls));
	return std::max(0.0, 100.0 - penalty);
}
}  // namespace

void NetMonitor::Series::push(double value)
{
	values.push_back(value);
	if (values.size() > kHistory)
		values.pop_front();
}

NetMonitor::NetMonitor(const PacketEngine& engine, const PacketEngineOptions& options)
: engine_(engine)
, options_(options)
{
}

NetMonitor::~NetMonitor()
{
	stop();
}

bool NetMonitor::is_toggle_key(int key) const
{
	const int configured = options_.features.net_monitor.key;
	const int upper		 = key >= 'a' && key <= 'z' ? key - 'a' + 'A' : key;
	return options_.features.net_monitor.enabled && upper == configured;
}

void NetMonitor::toggle()
{
	if (active_)
	{
		stop();
		return;
	}

	backend::ProfileFilter spec;
	spec.user_filter		= "tcp or udp";
	spec.include_bare_acks	= true;
	spec.client_enforcement = backend::ClientAddressEnforcement::none;
	spec.server_direction	= backend::ServerDirection::both;
	for (const ServerOptions& server : options_.servers)
		spec.server_addresses.push_back(server.address);
	if (spec.server_addresses.empty())
	{
		LOG_WARN("Net monitor: no servers are configured, there is nothing to measure.");
		return;
	}

	backend::OpenOptions open_options;
	open_options.filter			 = backend::filters::profile(spec);
	open_options.sniff			 = true;
	open_options.include_forward = true;
	std::string open_error;
	channel_ = backend::open(open_options, open_error);
	if (!channel_)
	{
		LOG_ERROR("Net monitor: failed to open the capture channel: %s", open_error.c_str());
		return;
	}

	{
		std::lock_guard<std::mutex> lock(mutex_);
		servers_.clear();
		server_order_.clear();
		for (const ServerOptions& server : options_.servers)
		{
			if (servers_.count(server.address))
				continue;
			servers_[server.address].label = server.name.empty() || server.name == server.address ? server.address : server.name;
			server_order_.push_back(server.address);
		}
		reset_locked();
	}
	paused_			 = false;
	stopping_		 = false;
	reset_requested_ = false;

	logging::set_suspended(true);
	std::printf("\033[?1049h\033[?25l");
	std::fflush(stdout);
	active_			= true;
	capture_thread_ = std::thread(&NetMonitor::capture_loop, this);
	render_thread_	= std::thread(&NetMonitor::render_loop, this);
}

void NetMonitor::stop()
{
	if (!active_)
		return;
	stopping_ = true;
	channel_->shutdown_recv();
	if (capture_thread_.joinable())
		capture_thread_.join();
	if (render_thread_.joinable())
		render_thread_.join();
	channel_->close();
	channel_.reset();
	active_ = false;
	std::printf("\033[?25h\033[?1049l");
	std::fflush(stdout);
	logging::set_suspended(false);
}

void NetMonitor::handle_key(int key)
{
	if (key == platform::key::space)
	{
		if (paused_)
		{
			// Measurements taken before the pause must not be paired with packets seen after it.
			std::lock_guard<std::mutex> lock(mutex_);
			clear_transient_locked();
			last_tick_		 = Clock::now();
			system_has_prev_ = false;
			paused_			 = false;
		}
		else
		{
			std::lock_guard<std::mutex> lock(mutex_);
			paused_at_ = Clock::now();
			paused_	   = true;
		}
	}
	else if (key == 'r' || key == 'R')
		reset_requested_ = true;
}

void NetMonitor::reset_locked()
{
	for (auto& entry : servers_)
	{
		const std::string label = entry.second.label;
		entry.second			= ServerStats{};
		entry.second.label		= label;
	}
	total_ = ServerStats{};
	ports_.clear();
	std::fill(std::begin(size_up_), std::end(size_up_), 0);
	std::fill(std::begin(size_down_), std::end(size_down_), 0);
	peak_bps_up_	 = 0;
	peak_bps_down_	 = 0;
	peak_pps_		 = 0;
	sum_pps_		 = 0;
	queued_			 = Series{};
	peak_queued_	 = 0;
	cpu_			 = Series{};
	nic_problems_	 = Series{};
	system_has_prev_ = false;
	total_packets_	 = 0;
	other_packets_	 = 0;
	elapsed_ticks_	 = 0;
	last_tick_		 = Clock::now();
}

void NetMonitor::clear_transient_locked()
{
	for (auto& entry : servers_)
	{
		entry.second.flows.clear();
		entry.second.has_in	 = false;
		entry.second.has_out = false;
	}
}

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
				platform::sleep_ms(10);
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
		return;
	const auto now = Clock::now();

	std::lock_guard<std::mutex> lock(mutex_);
	++total_packets_;
	// The direction comes from which endpoint is the server: the backend flag is unreliable for forwarded traffic,
	// which the nfqueue backend always reports as outbound.
	bool		 outbound = false;
	auto		 found	  = servers_.find(endpoint_address(parsed, false));
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
		const uint16_t server_port = parsed.tcp ? swap_u16(outbound ? parsed.tcp->DstPort : parsed.tcp->SrcPort)
												: swap_u16(outbound ? parsed.udp->DstPort : parsed.udp->SrcPort);
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

	if (!outbound)
	{
		if (stats.has_in)
		{
			const double gap = elapsed_ms(stats.last_in, now);
			stats.max_gap_ms = std::max(stats.max_gap_ms, gap);
			if (gap >= kStallMs)
				++stats.stalls;
			if (stats.prev_gap_ms > 0)
				stats.interarrival_jitter_ms += (std::fabs(gap - stats.prev_gap_ms) - stats.interarrival_jitter_ms) / 16.0;
			stats.prev_gap_ms = gap;
		}
		stats.last_in = now;
		stats.has_in  = true;
	}
	else
	{
		stats.last_out = now;
		stats.has_out  = true;
	}

	if (parsed.udp)
	{
		++stats.udp_packets;
		return;
	}
	if (!parsed.tcp)
		return;
	++stats.tcp_packets;

	const TcpHeader& tcp	= *parsed.tcp;
	const uint16_t	 source = swap_u16(tcp.SrcPort);
	const uint16_t	 dest	= swap_u16(tcp.DstPort);
	const uint64_t	 key	= outbound ? (static_cast<uint64_t>(source) << 16 | dest) : (static_cast<uint64_t>(dest) << 16 | source);
	if (stats.flows.size() >= kMaxFlowsPerServer && !stats.flows.count(key))
		stats.flows.erase(stats.flows.begin());
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
	Flow&		   flow	   = stats.flows[key];
	const uint32_t seq	   = swap_u32(tcp.SeqNum);
	const uint32_t payload = payload_length(parsed, length);
	const uint32_t end_seq = seq + payload + tcp.Syn + tcp.Fin;

	if (tcp.Rst)
	{
		++stats.resets;
		flow.closed = true;
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
		if (payload > 0)
			++stats.data_up;
		if (flow.out_seen && !seq_gt(end_seq, flow.highest_out_end))
		{
			// A retransmission makes any ACK for these bytes ambiguous, so they must not produce an RTT sample.
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

	if (payload > 0)
		++stats.data_down;
	if (end_seq != seq)
	{
		if (flow.in_seen && !seq_gt(end_seq, flow.highest_in_end))
			++stats.retrans_down;
		else
		{
			flow.in_seen		= true;
			flow.highest_in_end = end_seq;
		}
	}
	if (!tcp.Ack)
		return;
	const uint32_t	  ack = swap_u32(tcp.AckNum);
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
	++stats.tick_rtt_count;
	if (port_stats)
	{
		++port_stats->rtt_samples;
		port_stats->rtt_sum_ms += rtt;
		port_stats->last_rtt_ms = rtt;
		port_stats->tick_rtt_sum_ms += rtt;
		++port_stats->tick_rtt_count;
	}
	stats.recent_rtt.push_back(rtt);
	if (stats.recent_rtt.size() > kRttWindow)
		stats.recent_rtt.pop_front();
}

void NetMonitor::tick()
{
	double	 rtt_sum   = 0;
	uint32_t rtt_count = 0;
	double	 total_rtt = total_.last_rtt_ms;
	uint64_t retrans   = 0;
	uint64_t flows_new = 0;
	double	 pps_up = 0, pps_down = 0, bps_up = 0, bps_down = 0;
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
			rtt_sum += stats.tick_rtt_sum_ms;
			rtt_count += stats.tick_rtt_count;
		}
		else
			stats.rtt.push(last_value(stats.rtt.values));
		const uint64_t retrans_now = stats.retrans_up + stats.retrans_down;
		stats.retrans.push(static_cast<double>(retrans_now - stats.retrans_prev));
		retrans += retrans_now - stats.retrans_prev;
		stats.retrans_prev = retrans_now;
		if (stats.up.packets + stats.down.packets > 0)
		{
			const double data = static_cast<double>(stats.data_up + stats.data_down);
			stats.score.push(stability_score(data > 0 ? 100.0 * static_cast<double>(retrans_now) / data : 0, stats.jitter_ms,
											 stats.interarrival_jitter_ms, stats.resets, stats.stalls));
		}
		pps_up += static_cast<double>(stats.up.packets_tick);
		pps_down += static_cast<double>(stats.down.packets_tick);
		bps_up += static_cast<double>(stats.up.bytes_tick);
		bps_down += static_cast<double>(stats.down.bytes_tick);
		stats.up.packets_tick = stats.down.packets_tick = 0;
		stats.up.bytes_tick = stats.down.bytes_tick = 0;
		stats.tick_rtt_sum_ms						= 0;
		stats.tick_rtt_count						= 0;
	}
	for (auto& entry : ports_)
	{
		PortStats& port = entry.second;
		port.pps.push(static_cast<double>(port.up.packets_tick + port.down.packets_tick));
		if (port.tick_rtt_count > 0)
			port.rtt.push(port.tick_rtt_sum_ms / port.tick_rtt_count);
		else
			port.rtt.push(last_value(port.rtt.values));
		port.pkts_up   = static_cast<double>(port.up.packets_tick);
		port.pkts_down = static_cast<double>(port.down.packets_tick);
		port.rate_up   = static_cast<double>(port.up.bytes_tick);
		port.rate_down = static_cast<double>(port.down.bytes_tick);
		port.up.packets_tick = port.down.packets_tick = 0;
		port.up.bytes_tick = port.down.bytes_tick = 0;
		port.tick_rtt_sum_ms = 0;
		port.tick_rtt_count	 = 0;
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
		nic_problems_.push(system.nic_available
							   ? static_cast<double>((system.nic_errors + system.nic_drops) - (system_prev_.nic_errors + system_prev_.nic_drops))
							   : 0);
	}
	system_prev_	 = system;
	system_has_prev_ = true;

	if (rtt_count > 0)
		total_rtt = rtt_sum / rtt_count;
	total_.last_rtt_ms = total_rtt;
	total_.pps_up.push(pps_up);
	total_.pps_down.push(pps_down);
	total_.bps_up.push(bps_up);
	total_.bps_down.push(bps_down);
	total_.rtt.push(total_rtt);
	total_.retrans.push(static_cast<double>(retrans));
	total_.flows_new.push(static_cast<double>(flows_new));
	++elapsed_ticks_;
}

void NetMonitor::render_loop()
{
	while (!stopping_)
	{
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
			frame = render_frame(platform::console_width(), platform::console_height());
		}
		std::fwrite(frame.data(), 1, frame.size(), stdout);
		std::fflush(stdout);
		std::this_thread::sleep_for(kFrameInterval);
	}
}

std::string NetMonitor::render_frame(int console_columns, int console_rows)
{
	const size_t width		= static_cast<size_t>(console_columns > 0 ? std::max(console_columns, 60) : 100);
	const bool	 paused		= paused_;
	const std::string close_key = format_key(options_.features.net_monitor.key);
	// While paused, silence is measured up to the moment of the pause.
	const auto	 now		= paused ? paused_at_ : Clock::now();
	const size_t label_cols = std::clamp<size_t>(width / 8, 16, 24);
	const size_t value_cols = 13;
	const size_t chart_cols = std::min<size_t>(kHistory, width - label_cols - value_cols - 4);

	std::string out  = "\033[H";
	auto		line = [&out](const std::string& text) { out += text + "\033[K\n"; };

	uint64_t packets_up = 0, packets_down = 0, bytes_up = 0, bytes_down = 0, resets = 0, tcp = 0, udp = 0;
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
	const size_t chart_count = 6 + (focus ? 5 : 0) + 1 + 2;
	const size_t table_rows	 = server_order_.size();
	size_t		 port_rows	 = std::max<size_t>(1, std::min<size_t>(ports_.size(), 6));
	const int	 base_lines	 = 3 + 1 + 6 + 1 + 1 + 1 + (focus ? 1 + 5 + 10 : 1) + 1 + (1 + 1 + static_cast<int>(port_rows) + 1) + 4 + 4 + 4 + 1 +
							   static_cast<int>(table_rows) + 1 + 1;
	const int	 spare		 = console_rows > 0 ? console_rows - 1 - base_lines : 0;
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

	line(std::string(kBold) + " NETMONITOR " + kReset + (paused ? std::string(kYellow) + "[PAUSED]" : std::string(kGreen) + "[MEASURING]") + kReset +
		 "  measured " + format_clock(elapsed_ticks_) + "  " + kDim + "space pause/resume | r reset | " + close_key + " close | q quit" + kReset);
	line(std::string(kDim) + " passive TCP/UDP statistics of " + std::to_string(servers_.size()) + " configured server(s); " +
		 std::to_string(other_packets_) + " packet(s) matched no server" + kReset);
	line("");

	auto chart = [&](const std::string& name, const std::string& value, const Series& series, double floor, const char* color) {
		const std::vector<std::string> rows = chart_rows(series.values, chart_cols, floor, color, rows_per_chart);
		for (size_t row = 0; row < rows.size(); ++row)
			line(" " + (row == 0 ? pad(name, label_cols) + pad_left(value, value_cols) : std::string(label_cols + value_cols, ' ')) + "  " + rows[row]);
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
			count += flow.second.closed ? 0 : 1;
		return count;
	};
	auto count_text = [](double value) { return std::to_string(static_cast<uint64_t>(value)); };
	auto score_of	= [](const ServerStats& stats) { return stats.score.values.empty() ? -1.0 : stats.score.values.back(); };
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
	chart("latency (RTT)", format_ms(total_.last_rtt_ms, total_.last_rtt_ms > 0), total_.rtt, 50, rtt_color(total_.last_rtt_ms));
	chart("retransmits/s", count_text(last_value(total_.retrans.values)), total_.retrans, 5, kRed);
	line(std::string(kDim) + " peak bandwidth  down " + format_rate(peak_bps_down_) + "   up " + format_rate(peak_bps_up_) + kReset);
	{
		char		 text[160];
		const double average = elapsed_ticks_ > 0 ? sum_pps_ / static_cast<double>(elapsed_ticks_) : 0;
		std::snprintf(text, sizeof(text), " burstiness  peak %.0f pkt/s vs average %.0f pkt/s (%.1fx)   up/down bytes %.2f", peak_pps_, average,
					  average > 0 ? peak_pps_ / average : 0.0, bytes_down > 0 ? static_cast<double>(bytes_up) / static_cast<double>(bytes_down) : 0.0);
		line(std::string(kDim) + text + kReset);
	}
	line("");

	if (focus)
	{
		const std::vector<double> window(focus->recent_rtt.begin(), focus->recent_rtt.end());
		const bool				  has_rtt = focus->rtt_samples > 0;
		const double			  average = has_rtt ? focus->rtt_sum_ms / static_cast<double>(focus->rtt_samples) : 0;
		const double			  loss_up = 100.0 * static_cast<double>(focus->retrans_up) / static_cast<double>(std::max<uint64_t>(1, focus->data_up));
		const double			  loss_down = 100.0 * static_cast<double>(focus->retrans_down) / static_cast<double>(std::max<uint64_t>(1, focus->data_down));
		const uint64_t			  packets = focus->up.packets + focus->down.packets;
		const uint64_t			  bytes	  = focus->up.bytes + focus->down.bytes;

		line(std::string(kBold) + " Selected server: " + kReset + focus->label + " [" + focus_address + "]");
		chart("latency (RTT)", format_ms(focus->last_rtt_ms, has_rtt), focus->rtt, 50, rtt_color(focus->last_rtt_ms));
		chart("packets/s down", count_text(last_value(focus->pps_down.values)), focus->pps_down, 10, kCyan);
		chart("packets/s up", count_text(last_value(focus->pps_up.values)), focus->pps_up, 10, kCyan);
		chart("retransmits/s", count_text(last_value(focus->retrans.values)), focus->retrans, 5, kRed);
		chart("new flows/s", count_text(last_value(focus->flows_new.values)), focus->flows_new, 2, kYellow);
		line(" RTT min/avg/p50/p95/max  " +
			 (has_rtt ? format_ms(focus->rtt_min_ms) + " / " + format_ms(average) + " / " + format_ms(percentile(window, 0.5)) + " / " +
							format_ms(percentile(window, 0.95)) + " / " + format_ms(focus->rtt_max_ms)
					  : std::string("no TCP round trip measured yet (UDP traffic has no RTT)")));
		line(" RTT jitter " + format_ms(focus->jitter_ms, has_rtt) + "   arrival jitter " + format_ms(focus->interarrival_jitter_ms, focus->has_in) +
			 "   silence " + (focus->has_in ? format_ms(elapsed_ms(focus->last_in, now)) : std::string("-")) + "   longest gap " +
			 format_ms(focus->max_gap_ms, focus->has_in));
		char loss[192];
		std::snprintf(loss, sizeof(loss), " retransmits  up %s%.2f%%%s (%llu)   down %s%.2f%%%s (%llu)   resets %llu", loss_color(loss_up), loss_up, kReset,
					  static_cast<unsigned long long>(focus->retrans_up), loss_color(loss_down), loss_down, kReset,
					  static_cast<unsigned long long>(focus->retrans_down), static_cast<unsigned long long>(focus->resets));
		line(loss);
		char handshake[160];
		if (focus->handshakes > 0)
			std::snprintf(handshake, sizeof(handshake), " handshakes  %llu   last %s   avg %s   min %s   max %s   SYN retries %llu   half-open %zu",
						  static_cast<unsigned long long>(focus->handshakes), format_ms(focus->last_handshake_ms).c_str(),
						  format_ms(focus->handshake_sum_ms / static_cast<double>(focus->handshakes)).c_str(), format_ms(focus->handshake_min_ms).c_str(),
						  format_ms(focus->handshake_max_ms).c_str(), static_cast<unsigned long long>(focus->syn_retries), half_open(*focus));
		else
			std::snprintf(handshake, sizeof(handshake), " handshakes  none seen yet (open a new connection to measure)   SYN retries %llu   half-open %zu",
						  static_cast<unsigned long long>(focus->syn_retries), half_open(*focus));
		line(handshake);
		line(" protocol  TCP " + std::to_string(focus->tcp_packets) + " | UDP " + std::to_string(focus->udp_packets) + "   avg packet " +
			 std::to_string(packets ? bytes / packets : 0) + " B   total " + std::to_string(packets) + " packets, " +
			 format_size(static_cast<double>(bytes)));
		line(" TCP health  duplicate ACKs up " + std::to_string(focus->dup_acks_up) + " / down " + std::to_string(focus->dup_acks_down) +
			 "   zero-window " + std::to_string(focus->zero_windows) + "   stalls (gap >= " + format_ms(kStallMs) + ") " + std::to_string(focus->stalls));
		line(" TCP flags   SYN " + std::to_string(focus->syn_packets) + "  FIN " + std::to_string(focus->fin_packets) + "  RST " +
			 std::to_string(focus->resets) + "  PSH " + std::to_string(focus->psh_packets) + "  pure ACK " + std::to_string(focus->pure_acks));
		const double minutes = elapsed_ticks_ > 0 ? static_cast<double>(elapsed_ticks_) / 60.0 : 0;
		char		 flows[160];
		std::snprintf(flows, sizeof(flows), " TCP flows   active %zu   opened %llu   churn %.1f/min (source port changes per minute)", active_flows(*focus),
					  static_cast<unsigned long long>(focus->flows_opened),
					  static_cast<double>(focus->flows_opened) / std::max(minutes, 1.0 / 60));
		line(flows);
		if (focus->last_ttl >= 0)
		{
			const int hops = initial_ttl(focus->last_ttl) - focus->last_ttl;
			line(" path        TTL " + std::to_string(focus->last_ttl) + " (~" + std::to_string(hops) + " hops)   route changes " +
				 std::to_string(focus->ttl_changes) + "   DSCP " + std::to_string(focus->last_dscp) + " (" + std::to_string(focus->dscp_changes) +
				 " changes)   ECN-CE marks " + std::to_string(focus->ecn_marked));
		}
		else
			line(std::string(kDim) + " path        no inbound packet seen yet" + kReset);
		const double score = score_of(*focus);
		char		 score_text[64];
		std::snprintf(score_text, sizeof(score_text), "%.0f/100", score);
		line(std::string(" stability   ") + (score >= 0 ? std::string(score_color(score)) + score_text + " " + score_arrow(*focus) + kReset : "-") +
			 kDim + "   (retransmits, jitter, stalls and resets since the view opened)" + kReset);
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
	line(std::string(kBold) + " Ports (server side, top " + std::to_string(port_rows) + " of " + std::to_string(ports_.size()) + ")" + kReset);
	line(std::string(kDim) + " " + pad("port", 22) + pad_left("pkt/s v", 9) + pad_left("pkt/s ^", 9) + pad_left("rate v", 14) + pad_left("rate ^", 14) +
		 pad_left("RTT", 10) + "  trend" + kReset);
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
		std::string	 text	  = std::string(" ") + (direction == 0 ? "down  " : "up    ");
		const size_t bar_cols = static_cast<size_t>(std::clamp<int>((static_cast<int>(width) - 8) / static_cast<int>(kSizeBuckets) - 18, 4, 40));
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
		std::string info = " profiles active " + std::to_string(active) + "/" + std::to_string(options_.profiles.size()) + "   queue peak " +
						   std::to_string(peak_queued_) + "   next release in " + format_ms(static_cast<double>(engine_.next_batch_in_ms()));
#ifdef LAGSW_FEATURE_PASSIVE_LATENCY
		if (engine_.is_passive_latency_enabled())
			info += "   passive latency " + engine_.passive_latency_status() + (engine_.is_passive_latency_paused() ? " [paused]" : "");
#endif
		line(info);
	}
	line("");

	line(std::string(kBold) + " This machine" + kReset);
	{
		char cpu[24];
		std::snprintf(cpu, sizeof(cpu), "%.1f%%", last_value(cpu_.values));
		chart("lagsw CPU", system_prev_.cpu_available ? cpu : "n/a", cpu_, 10, kGreen);
		chart("NIC errors+drops/s", system_prev_.nic_available ? count_text(last_value(nic_problems_.values)) : "n/a", nic_problems_, 5, kRed);
	}
	line("");

	const size_t name_cols	= std::clamp<size_t>(width / 5, 14, 40);
	const size_t trend_cols = std::min<size_t>(kHistory, width > name_cols + 75 ? width - name_cols - 75 : 0);
	line(std::string(kBold) + " " + pad("Server", name_cols) + pad_left("pkt/s v", 9) + pad_left("pkt/s ^", 9) + pad_left("RTT", 10) + pad_left("avg", 10) +
		 pad_left("jitter", 9) + pad_left("retx%", 8) + pad_left("silent", 9) + pad_left("score", 7) + "  RTT trend" + kReset);
	size_t shown = 0;
	for (const std::string& address : server_order_)
	{
		if (shown++ >= table_limit)
			break;
		const ServerStats& stats	= servers_.at(address);
		const bool		   seen		= stats.up.packets + stats.down.packets > 0;
		const double	   data		= static_cast<double>(stats.data_up + stats.data_down);
		const double	   retx		= data > 0 ? 100.0 * static_cast<double>(stats.retrans_up + stats.retrans_down) / data : 0;
		const bool		   has_rtt	= stats.rtt_samples > 0;
		const double	   average	= has_rtt ? stats.rtt_sum_ms / static_cast<double>(stats.rtt_samples) : 0;
		const bool		   current	= &stats == focus;
		const double	   score	= score_of(stats);
		char			   retx_text[16], score_text[16];
		std::snprintf(retx_text, sizeof(retx_text), "%.1f", retx);
		std::snprintf(score_text, sizeof(score_text), "%.0f", score);
		line(std::string(current ? kBold : "") + (current ? ">" : " ") + pad(stats.label, name_cols) + kReset +
			 pad_left(seen ? count_text(last_value(stats.pps_down.values)) : "-", 9) + pad_left(seen ? count_text(last_value(stats.pps_up.values)) : "-", 9) +
			 (has_rtt ? rtt_color(stats.last_rtt_ms) : kDim) + pad_left(format_ms(stats.last_rtt_ms, has_rtt), 10) + kReset +
			 pad_left(format_ms(average, has_rtt), 10) + pad_left(format_ms(stats.jitter_ms, has_rtt), 9) + (data > 0 ? loss_color(retx) : kDim) +
			 pad_left(data > 0 ? retx_text : "-", 8) + kReset + pad_left(stats.has_in ? format_ms(elapsed_ms(stats.last_in, now)) : "-", 9) +
			 (score >= 0 ? score_color(score) : kDim) + pad_left(score >= 0 ? score_text : "-", 7) + kReset + "  " +
			 sparkline(stats.rtt.values, trend_cols, 50, has_rtt ? rtt_color(stats.last_rtt_ms) : kDim));
	}
	line("");
	line(std::string(kDim) + " Totals: " + std::to_string(packets_down) + " down / " + std::to_string(packets_up) + " up packets, " +
		 format_size(static_cast<double>(bytes_down)) + " down / " + format_size(static_cast<double>(bytes_up)) + " up, TCP " + std::to_string(tcp) +
		 " / UDP " + std::to_string(udp) + ", resets " + std::to_string(resets) + kReset);
	out += "\033[J";
	return out;
}

#endif  // LAGSW_FEATURE_NET_MONITOR
