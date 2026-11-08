// Unit tests for the net monitor (src/net_monitor/): capture setup, passive RTT and retransmission measurement, pausing and
// rendering. The monitor runs against the in-memory backend from tests/engine.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef LAGSW_FEATURE_NET_MONITOR

#	include "fakes.h"
#	include "log.h"
#	include "net_monitor/internal.h"
#	include "packet_engine.h"
#	include "support/packets.h"
#	include "support/test.h"

// The tests look at the measured values directly instead of parsing the rendered screen; LAGSW_NET_MONITOR_TESTING makes the
// internals of NetMonitor public.
#	include "net_monitor.h"

namespace {
using namespace packets;
using fakes::wait_until;

constexpr std::array<uint8_t, 4> kServer		= {192, 168, 1, 20};
constexpr std::array<uint8_t, 4> kClient		= {10, 0, 0, 1};
const char*						 kServerAddress = "192.168.1.20";

PacketEngineOptions options_with_server()
{
	PacketEngineOptions options;
	ProfileOptions		profile;
	profile.name						 = "A";
	options.profiles					 = {profile};
	options.global_filter				 = "tcp";
	options.features.net_monitor.enabled = true;
	ServerOptions server;
	server.address	= kServerAddress;
	server.name		= "Test";
	options.servers = {server};
	return options;
}

Bytes to_server(uint32_t seq, uint32_t ack, uint8_t flags, size_t payload)
{
	return ipv4_packet(kTcp, tcp_segment(1000, 2000, seq, ack, flags, 5, payload), kClient, kServer);
}

Bytes from_server(uint32_t seq, uint32_t ack, uint8_t flags, size_t payload)
{
	return ipv4_packet(kTcp, tcp_segment(2000, 1000, seq, ack, flags, 5, payload), kServer, kClient);
}

void test_toggle_key_follows_the_configuration()
{
	PacketEngineOptions options		 = options_with_server();
	options.features.net_monitor.key = 'M';
	PacketEngine engine(options);
	NetMonitor	 monitor(engine, options);
	CHECK(monitor.is_toggle_key('M') && monitor.is_toggle_key('m'));
	CHECK(!monitor.is_toggle_key('N'));
	options.features.net_monitor.enabled = false;
	CHECK(!monitor.is_toggle_key('M'));
}

void test_no_capture_without_servers()
{
	fakes::reset();
	PacketEngineOptions options = options_with_server();
	options.servers.clear();
	PacketEngine engine(options);
	NetMonitor	 monitor(engine, options);
	monitor.toggle();
	CHECK(!monitor.active());
	CHECK(fakes::channels().empty());
}

void test_toggle_opens_and_closes_a_sniff_channel()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	CHECK(monitor.active());
	CHECK(fakes::channels().size() == 1);
	const auto channel = fakes::channel(0);
	CHECK(channel->options.sniff);
	const auto spec = fakes::last_profile_spec();
	CHECK(spec.include_bare_acks);
	CHECK(spec.server_addresses.size() == 1 && spec.server_addresses[0] == kServerAddress);
	monitor.toggle();
	CHECK(!monitor.active());
	CHECK(channel->closed());
}

void test_rtt_is_measured_from_data_to_ack()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	const auto channel = fakes::channel(0);

	channel->inject(to_server(100, 1, kAck | kPsh, 10), 1, true);
	CHECK(wait_until([&] { return channel->consumed() == 1; }));
	std::this_thread::sleep_for(std::chrono::milliseconds(40));
	channel->inject(from_server(1, 110, kAck, 0), 2, false);
	CHECK(wait_until([&] {
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		return monitor.servers_[kServerAddress].rtt_samples == 1;
	}));
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		const auto&					stats = monitor.servers_[kServerAddress];
		CHECK(stats.last_rtt_ms >= 35 && stats.last_rtt_ms < 500);
		CHECK(stats.up.packets == 1 && stats.down.packets == 1);
		CHECK(stats.tcp_packets == 2 && stats.data_up == 1);
	}
	monitor.stop();
}

#	ifdef LAGSW_FEATURE_PASSIVE_LATENCY
void test_monitor_and_profile_receive_packets_with_passive_latency()
{
	fakes::reset();
	PacketEngineOptions options = options_with_server();
	options.features.passive_latency.enabled = true;
	options.features.passive_latency.delay_ms = 20;
	PacketEngine engine(options);
	engine.start_workers();
	NetMonitor monitor(engine, options);
	monitor.toggle();
	engine.setup(1);

	const auto passive = fakes::channel_with_filter("tcp");
	const auto sniff = fakes::channel_with_filter("profile#0");
	const auto profile = fakes::channel_with_filter("profile#1");
	CHECK(passive && sniff && profile);
	if (!passive || !sniff || !profile)
		return;
	CHECK(sniff->options.sniff && !passive->options.sniff && !profile->options.sniff);
	CHECK(sniff->options.priority > passive->options.priority);
	CHECK(passive->options.priority > profile->options.priority);

	// Model WinDivert's priority traversal: sniff first, then reinject from the passive channel to the profile.
	const auto route = [&](const Bytes& packet, int64_t id, bool outbound) {
		sniff->inject(packet, id, outbound);
		passive->inject(packet, id, outbound);
		if (!wait_until([&] { return passive->sent_count() >= static_cast<size_t>(id); }))
			return false;
		const auto sent = passive->sent_packets();
		profile->inject(sent[static_cast<size_t>(id) - 1].data, id, outbound);
		return wait_until([&] { return profile->consumed() >= static_cast<size_t>(id); });
	};
	CHECK(route(to_server(100, 1, kAck | kPsh, 10), 1, true));
	CHECK(route(from_server(1, 110, kAck, 0), 2, false));
	CHECK(route(to_server(110, 1, kAck | kPsh, 10), 3, true));
	CHECK(route(from_server(1, 120, kAck, 0), 4, false));
	CHECK(wait_until([&] {
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		return monitor.servers_[kServerAddress].rtt_samples == 2;
	}));
	CHECK(profile->consumed() == 4);
	monitor.stop();
	engine.stop_workers();
}
#	endif

void test_direction_comes_from_the_server_address_not_the_backend_flag()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	const auto channel = fakes::channel(0);

	// Forwarded traffic is flagged outbound in both directions by the nfqueue backend.
	channel->inject(to_server(1, 1, kAck | kPsh, 10), 1, true);
	channel->inject(from_server(1, 11, kAck | kPsh, 10), 2, true);
	CHECK(wait_until([&] { return channel->consumed() == 2; }));
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		const auto&					stats = monitor.servers_[kServerAddress];
		CHECK(stats.up.packets == 1 && stats.down.packets == 1);
		CHECK(monitor.other_packets_ == 0);
	}
	monitor.stop();
}

void test_retransmissions_are_counted_and_not_sampled()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	const auto channel = fakes::channel(0);

	channel->inject(to_server(100, 1, kAck | kPsh, 10), 1, true);
	channel->inject(to_server(100, 1, kAck | kPsh, 10), 2, true);
	channel->inject(from_server(500, 110, kAck | kPsh, 20), 3, false);
	channel->inject(from_server(500, 110, kAck | kPsh, 20), 4, false);
	CHECK(wait_until([&] { return channel->consumed() == 4; }));
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		const auto&					stats = monitor.servers_[kServerAddress];
		CHECK(stats.retrans_up == 1);
		CHECK(stats.retrans_down == 1);
		CHECK(stats.rtt_samples == 0);
		CHECK(stats.data_up == 2 && stats.data_down == 2);
	}
	monitor.stop();
}

void test_pause_ignores_packets_and_reset_clears_them()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	const auto channel = fakes::channel(0);

	monitor.handle_key(platform::key::space);
	channel->inject(to_server(1, 1, kAck, 0), 1, true);
	CHECK(wait_until([&] { return channel->consumed() == 1; }));
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		CHECK(monitor.servers_[kServerAddress].up.packets == 0);
	}
	monitor.handle_key(platform::key::space);
	channel->inject(to_server(1, 1, kAck, 0), 2, true);
	CHECK(wait_until([&] {
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		return monitor.servers_[kServerAddress].up.packets == 1;
	}));
	monitor.handle_key('r');
	CHECK(wait_until([&] {
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		return monitor.servers_[kServerAddress].up.packets == 0;
	}));
	monitor.stop();
}

void test_view_keys_follow_the_configuration()
{
	fakes::reset();
	PacketEngineOptions options			   = options_with_server();
	options.features.net_monitor.pause_key = 'G';
	options.features.net_monitor.reset_key = 'H';
	options.features.net_monitor.flows_key = 'J';
	PacketEngine engine(options);
	NetMonitor	 monitor(engine, options);
	monitor.toggle();

	CHECK(monitor.handle_key('g'));
	CHECK(monitor.paused_);
	CHECK(monitor.handle_key('G'));
	CHECK(!monitor.paused_);
	CHECK(!monitor.handle_key(platform::key::space));
	CHECK(!monitor.handle_key('r'));
	CHECK(!monitor.handle_key('f'));
	CHECK(monitor.handle_key('h'));
	CHECK(monitor.handle_key('j'));
	monitor.stop();
}

void test_charts_and_frame_render()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	engine.cycle_server(1);
	NetMonitor monitor(engine, options);
	monitor.toggle();
	monitor.stop();
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		auto&						stats = monitor.servers_[kServerAddress];
		stats.up.packets_tick			  = 5;
		stats.down.packets_tick			  = 50;
		stats.rtt_samples				  = 1;
		stats.last_rtt_ms				  = 42;
		stats.recent_rtt.push_back(42);
		monitor.tick();
		monitor.tick();
		CHECK(stats.pps_down.values.size() == 2 && stats.pps_down.values[0] == 50 && stats.pps_down.values[1] == 0);
		CHECK(monitor.total_.pps_up.values[0] == 5);
		const std::string frame = monitor.render_frame(120, 0);
		CHECK(frame.find("NETMONITOR") != std::string::npos);
		CHECK(frame.find("Test [192.168.1.20]") != std::string::npos);
		CHECK(frame.find("42 ms") != std::string::npos);
		CHECK(frame.find("▁") != std::string::npos || frame.find("█") != std::string::npos);

		// A taller, wider terminal makes the charts taller and wider but never produces more lines than rows.
		const auto		  count_lines = [](const std::string& text) { return std::count(text.begin(), text.end(), '\n'); };
		const std::string small		  = monitor.render_frame(100, 0);
		const std::string tall		  = monitor.render_frame(200, 100);
		CHECK(count_lines(tall) > count_lines(small));
		CHECK(count_lines(tall) <= 99);
		const std::string cramped = monitor.render_frame(100, 40);
		CHECK(count_lines(cramped) <= count_lines(small));
		CHECK(frame.find("Ports") != std::string::npos);
		CHECK(frame.find("Packet sizes") != std::string::npos);
		CHECK(frame.find("lagsw effect") != std::string::npos);
		CHECK(frame.find("bit/s") != std::string::npos);
	}
}

void test_silent_server_row()
{
	using namespace net_monitor_detail;
	fakes::reset();
	PacketEngineOptions options = options_with_server();
	CHECK(options.features.net_monitor.silent_timeout_ms == 30000);
	PacketEngine engine(options);
	NetMonitor	 monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	auto& stats = monitor.servers_[kServerAddress];
	stats.up.packets = 10;
	stats.down.packets = 20;
	stats.has_silence = true;
	stats.pps_up.push(12);
	stats.pps_down.push(34);
	stats.rtt_samples = 2;
	stats.last_rtt_ms = 42;
	stats.rtt_sum_ms = 100;
	stats.jitter_ms = 8;
	stats.data_up = 20;
	stats.retrans_up = 1;
	stats.rtt.push(42);
	stats.score.push(87);
	stats.alert_active[NetMonitor::alert_rtt] = true;
	monitor.paused_ = true;
	monitor.paused_at_ = Clock::now();

	const auto row = [&] {
		const std::string frame = monitor.render_frame(120, 0);
		const size_t label = frame.find("!Test");
		CHECK(label != std::string::npos);
		if (label == std::string::npos)
			return std::string();
		const size_t start = frame.rfind('\n', label);
		const size_t end = frame.find('\n', label);
		return frame.substr(start + 1, end - start - 1);
	};
	stats.last_in = monitor.paused_at_ - std::chrono::milliseconds(29999);
	CHECK(row().find(std::string(kRed) + "!Test") == 0);
	stats.last_in = monitor.paused_at_ - std::chrono::milliseconds(30000);
	const std::string expected = std::string(kDim) + "!" + pad(stats.label, 24) + std::string(18, ' ') +
		pad_left("42 ms", 10) + std::string(27, ' ') + pad_left("30.0 s", 9) + pad_left("87", 7) + "  " +
		std::string(21, ' ') + kReset + "\033[K";
	CHECK(row() == expected);
	CHECK(stats.rtt.values.size() == 1 && stats.data_up == 20);

	options.features.net_monitor.silent_timeout_ms = 40000;
	CHECK(row().find(std::string(kRed) + "!Test") == 0);
	stats.last_in = monitor.paused_at_ - std::chrono::milliseconds(40000);
	CHECK(row().find(std::string(kDim) + "!Test") == 0);
	options.features.net_monitor.silent_timeout_ms = 0;
	CHECK(row().find(std::string(kRed) + "!Test") == 0);
	options.features.net_monitor.silent_timeout_ms = 30000;
	stats.has_silence = false;
	CHECK(row().find(std::string(kRed) + "!Test") == 0);
	stats.has_silence = true;
	stats.rtt_samples = 0;
	stats.score.values.clear();
	const std::string no_samples = std::string(kDim) + "!" + pad(stats.label, 24) + std::string(18, ' ') +
		pad_left("-", 10) + std::string(27, ' ') + pad_left("40.0 s", 9) + pad_left("-", 7) + "  " +
		std::string(21, ' ') + kReset + "\033[K";
	CHECK(row() == no_samples);

	// Resuming excludes paused time without restoring the interarrival state.
	monitor.paused_at_ = Clock::now() - std::chrono::minutes(2);
	stats.last_in = monitor.paused_at_ - std::chrono::seconds(30);
	stats.has_in = true;
	CHECK(monitor.handle_key(platform::key::space));
	CHECK(!stats.has_in);
	CHECK(elapsed_ms(stats.last_in, Clock::now()) >= 30000 && elapsed_ms(stats.last_in, Clock::now()) < 31000);
	CHECK(row().find(std::string(kDim) + "!Test") == 0);
	const Bytes inbound = from_server(1, 1, kAck, 0);
	monitor.record(inbound.data(), static_cast<uint32_t>(inbound.size()));
	CHECK(row().find(std::string(kRed) + "!Test") == 0);
}

#if defined(LAGSW_FEATURE_SERVER_DISCOVERY) && defined(LAGSW_FEATURE_REGION_ENFORCEMENT)
void test_probes_do_not_update_silence_or_alerts()
{
	using namespace net_monitor_detail;
	fakes::reset();
	PacketEngineOptions options = options_with_server();
	options.features.server_discovery.port = 2000;
	options.features.region_enforcement.probe_port = 3000;
	options.features.net_monitor.alert_rtt_ms = 100;
	options.features.net_monitor.alert_stall_ms = 500;
	PacketEngine engine(options);
	NetMonitor monitor(engine, options);
	monitor.toggle();
	monitor.stop();
	auto& stats = monitor.servers_[kServerAddress];
	const auto feed_packet = [&](const Bytes& packet) { monitor.record(packet.data(), static_cast<uint32_t>(packet.size())); };
	const auto tcp_out = [&](uint16_t port, uint32_t seq) {
		return ipv4_packet(kTcp, tcp_segment(1000, port, seq, 1, kAck | kPsh, 5, 10), kClient, kServer);
	};
	const auto tcp_in = [&](uint16_t port, uint32_t ack) {
		return ipv4_packet(kTcp, tcp_segment(port, 1000, 1, ack, kAck), kServer, kClient);
	};
	const auto udp_in = [&](uint16_t port) {
		return ipv4_packet(kUdp, udp_datagram(port, 1000, 10), kServer, kClient);
	};

	// Probe traffic has RTT and retransmits of its own, but cannot create server alerts or a silence timestamp.
	feed_packet(tcp_out(3000, 100));
	auto& probe_flow = stats.flows[(uint64_t{1000} << 16) | 3000];
	probe_flow.pending.front().sent -= std::chrono::seconds(1);
	feed_packet(tcp_in(3000, 110));
	for (int i = 0; i < 21; ++i)
		feed_packet(tcp_out(3000, 200));
	feed_packet(udp_in(3000));
	feed_packet(udp_in(4000));
	monitor.tick();
	CHECK(stats.down.packets == 3 && stats.up.packets == 22);
	CHECK(monitor.ports_.at((1u << 16) | 3000).rtt_samples == 1);
	CHECK(probe_flow.rtt_samples == 1);
	CHECK(!stats.has_silence && stats.rtt_samples == 0 && stats.data_up == 0 && stats.retrans_up == 0);
	for (int kind = 0; kind < NetMonitor::alert_kinds; ++kind)
		CHECK(!stats.alert_active[kind] && stats.alert_count[kind] == 0);

	// The main port drives silence and alerts, even while probes continue.
	feed_packet(udp_in(2000));
	CHECK(stats.has_silence);
	stats.last_in -= std::chrono::seconds(31);
	const auto last_main = stats.last_in;
	feed_packet(udp_in(3000));
	feed_packet(udp_in(4000));
	CHECK(stats.last_in == last_main);
	const std::string frame = monitor.render_frame(120, 0);
	CHECK(frame.find(std::string(kDim) + " Test") != std::string::npos);
	feed_packet(udp_in(2000));
	CHECK(stats.last_in > last_main && stats.tick_max_gap_ms >= 31000);
	feed_packet(tcp_out(2000, 100));
	stats.flows[(uint64_t{1000} << 16) | 2000].pending.front().sent -= std::chrono::seconds(1);
	feed_packet(tcp_in(2000, 110));
	for (int i = 0; i < 21; ++i)
		feed_packet(tcp_out(2000, 200));
	monitor.tick();
	CHECK(stats.alert_active[NetMonitor::alert_stall]);
	CHECK(stats.alert_active[NetMonitor::alert_rtt]);
	CHECK(stats.alert_active[NetMonitor::alert_retransmit]);
	const double main_rtt = stats.last_rtt_ms;
	const double main_jitter = stats.jitter_ms;
	const uint64_t main_samples = stats.rtt_samples;
	const uint64_t main_retransmits = stats.retrans_up;
	feed_packet(tcp_out(3000, 300));
	probe_flow.pending.front().sent -= std::chrono::seconds(3);
	feed_packet(tcp_in(3000, 310));
	CHECK(stats.last_rtt_ms == main_rtt && stats.jitter_ms == main_jitter && stats.rtt_samples == main_samples);
	CHECK(stats.retrans_up == main_retransmits);

	// Without a configured main port, only the configured probe port is excluded.
	monitor.reset_locked();
	options.features.server_discovery.port = 0;
	feed_packet(udp_in(3000));
	CHECK(!stats.has_silence);
	feed_packet(udp_in(4000));
	CHECK(stats.has_silence);
}
#endif

void test_ports_sizes_and_handshakes()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	const auto feed = [&](const Bytes& packet) { monitor.record(packet.data(), static_cast<uint32_t>(packet.size())); };
	feed(to_server(100, 0, kSyn, 0));
	feed(to_server(100, 0, kSyn, 0));
	std::this_thread::sleep_for(std::chrono::milliseconds(30));
	feed(from_server(500, 101, kSyn | kAck, 0));
	feed(ipv4_packet(kUdp, udp_datagram(4000, 3074, 20), kClient, kServer));
	feed(ipv4_packet(kUdp, udp_datagram(3074, 4000, 1200), kServer, kClient));
	feed(to_server(101, 501, kAck | kPsh, 600));

	std::lock_guard<std::mutex> lock(monitor.mutex_);
	const auto&					stats = monitor.servers_[kServerAddress];
	CHECK(stats.handshakes == 1);
	CHECK(stats.last_handshake_ms >= 25 && stats.last_handshake_ms < 500);
	CHECK(stats.syn_retries == 1);

	CHECK(monitor.ports_.size() == 2);
	CHECK(monitor.ports_.count((1u << 16) | 2000) == 1);
	const auto udp = monitor.ports_.find(3074);
	CHECK(udp != monitor.ports_.end());
	if (udp != monitor.ports_.end())
		CHECK(!udp->second.tcp && udp->second.up.packets == 1 && udp->second.down.packets == 1);

	CHECK(monitor.size_down_[3] == 1);
	CHECK(monitor.size_up_[2] == 1);
	CHECK(monitor.size_up_[0] >= 3);
	monitor.tick();
	CHECK(monitor.render_frame(120, 60).find("udp/3074 xbox live") != std::string::npos);
}

void test_tcp_health_flows_and_path()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	engine.cycle_server(1);
	NetMonitor monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	const auto feed = [&](const Bytes& packet) { monitor.record(packet.data(), static_cast<uint32_t>(packet.size())); };
	feed(to_server(100, 0, kSyn, 0));
	feed(from_server(500, 101, kSyn | kAck, 0));
	feed(to_server(101, 501, kAck | kPsh, 100));
	// The server keeps acknowledging the same byte: two duplicate ACKs.
	feed(from_server(501, 101, kAck, 0));
	feed(from_server(501, 101, kAck, 0));
	feed(from_server(501, 101, kAck, 0));
	feed(to_server(201, 501, kRst, 0));

	std::lock_guard<std::mutex> lock(monitor.mutex_);
	const auto&					stats = monitor.servers_[kServerAddress];
	CHECK(stats.syn_packets == 2 && stats.psh_packets == 1 && stats.resets == 1);
	CHECK(stats.dup_acks_down == 2);
	CHECK(stats.flows_opened == 1);
	CHECK(stats.flows.begin()->second.closed);
	CHECK(stats.last_ttl >= 0);
	monitor.tick();
	CHECK(stats.flows_new.values.back() == 1);
	CHECK(!stats.score.values.empty() && stats.score.values.back() <= 100);
	const std::string frame = monitor.render_frame(140, 90);
	CHECK(frame.find("TCP health") != std::string::npos);
	CHECK(frame.find("This machine") != std::string::npos);
	CHECK(frame.find("burstiness") != std::string::npos);
	CHECK(monitor.cpu_.values.empty());	 // the first sample only sets the baseline
}

void feed(NetMonitor& monitor, const Bytes& packet)
{
	monitor.record(packet.data(), static_cast<uint32_t>(packet.size()));
}

void test_capture_health_and_warnings()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	const std::vector<uint8_t> garbage = {0x00, 0x01, 0x02};
	monitor.record(garbage.data(), static_cast<uint32_t>(garbage.size()));
	feed(monitor, ipv4_packet(kTcp, tcp_segment(1000, 2000, 1, 1, kAck), kClient, {8, 8, 8, 8}));

	std::lock_guard<std::mutex> lock(monitor.mutex_);
	CHECK(monitor.unparsed_packets_ == 1 && monitor.other_packets_ == 1);
	std::string frame = monitor.render_frame(120, 0);
	CHECK(frame.find("capture ") != std::string::npos && frame.find("unparsed 1") != std::string::npos);
	CHECK(frame.find("no packets from the configured servers") == std::string::npos);
	for (int i = 0; i < 5; ++i)
		monitor.tick();
	CHECK(monitor.render_frame(120, 0).find("no packets from the configured servers") != std::string::npos);
}

void test_one_sided_capture_is_called_out()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	feed(monitor, to_server(1, 1, kAck | kPsh, 10));
	std::lock_guard<std::mutex> lock(monitor.mutex_);
	for (int i = 0; i < 10; ++i)
		monitor.tick();
	const std::string frame = monitor.render_frame(120, 0);
	CHECK(frame.find("no inbound ones") != std::string::npos);
}

void test_resize_is_not_needed_for_the_layout_to_fit()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	engine.cycle_server(1);
	NetMonitor monitor(engine, options);
	monitor.toggle();
	monitor.stop();
	std::lock_guard<std::mutex> lock(monitor.mutex_);
	monitor.tick();
	const auto count_lines = [](const std::string& text) { return std::count(text.begin(), text.end(), '\n'); };
	for (const int rows : {62, 80, 100})
		CHECK(count_lines(monitor.render_frame(120, rows)) <= rows - 1);
	CHECK(count_lines(monitor.render_flow_view(120, 30)) <= 29);
}

void test_alerts_raise_and_clear()
{
	fakes::reset();
	PacketEngineOptions options							  = options_with_server();
	options.features.net_monitor.alert_rtt_ms			  = 100;
	options.features.net_monitor.alert_jitter_ms		  = 20;
	options.features.net_monitor.alert_retransmit_percent = 10;
	options.features.net_monitor.alert_stall_ms			  = 500;
	PacketEngine engine(options);
	NetMonitor	 monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	std::lock_guard<std::mutex> lock(monitor.mutex_);
	auto&						stats = monitor.servers_[kServerAddress];
	stats.rtt_samples				  = 1;
	stats.tick_rtt_sum_ms			  = 300;
	stats.tick_rtt_count			  = 1;
	stats.jitter_ms					  = 40;
	stats.data_up					  = 40;
	stats.retrans_up				  = 10;
	stats.tick_max_gap_ms			  = 900;
	monitor.tick();
	for (const auto kind : {NetMonitor::alert_rtt, NetMonitor::alert_jitter, NetMonitor::alert_retransmit, NetMonitor::alert_stall})
		CHECK(stats.alert_active[kind] && stats.alert_count[kind] == 1);
	CHECK(monitor.events_.size() == 4 && monitor.events_.back().level == NetMonitor::Event::Level::alert);
	CHECK(monitor.alerts_active_.values.back() == 4);
	CHECK(monitor.render_frame(120, 0).find("!Test") != std::string::npos);

	// Staying above the limit does not raise the alert again; dropping below clears it.
	stats.tick_rtt_sum_ms = 400;
	stats.tick_rtt_count  = 1;
	monitor.tick();
	CHECK(stats.alert_count[NetMonitor::alert_rtt] == 1 && monitor.events_.size() == 5);  // only the stall cleared, as its gap was reset
	stats.tick_rtt_sum_ms = 40;
	stats.tick_rtt_count  = 1;
	stats.jitter_ms		  = 1;
	monitor.tick();
	CHECK(!stats.alert_active[NetMonitor::alert_rtt] && !stats.alert_active[NetMonitor::alert_jitter]);
	CHECK(!stats.alert_active[NetMonitor::alert_stall]);
	CHECK(monitor.events_.back().level == NetMonitor::Event::Level::ok);
	CHECK(monitor.alerts_active_.values.back() == 1);  // the retransmit window still covers the earlier burst
}

void test_alerts_can_be_disabled()
{
	fakes::reset();
	PacketEngineOptions options					 = options_with_server();
	options.features.net_monitor.alert_rtt_ms	 = 0;
	options.features.net_monitor.alert_jitter_ms = 0;
	options.features.net_monitor.alert_stall_ms	 = 0;
	PacketEngine engine(options);
	NetMonitor	 monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	std::lock_guard<std::mutex> lock(monitor.mutex_);
	auto&						stats = monitor.servers_[kServerAddress];
	stats.rtt_samples				  = 1;
	stats.tick_rtt_sum_ms			  = 5000;
	stats.tick_rtt_count			  = 1;
	stats.jitter_ms					  = 500;
	stats.tick_max_gap_ms			  = 9000;
	monitor.tick();
	CHECK(monitor.events_.empty());
}

void test_profile_changes_become_events_and_markers()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	std::lock_guard<std::mutex> lock(monitor.mutex_);
	monitor.tick();
	CHECK(monitor.events_.empty() && monitor.profile_active_.values.back() == 0);
	// The monitor believed the profile was running; the engine says it is not, so this reads as a deactivation.
	monitor.profile_state_.assign(1, true);
	monitor.tick();
	CHECK(monitor.events_.size() == 1 && monitor.events_.back().text == "profile 'A' deactivated");
	const std::string frame = monitor.render_frame(120, 0);
	CHECK(frame.find("profiles active") != std::string::npos && frame.find("profile 'A' deactivated") != std::string::npos);
}

void test_profile_view_tracks_activations_and_conditions()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	// One second without a profile becomes the baseline.
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		auto&						stats = monitor.servers_[kServerAddress];
		stats.tick_rtt_sum_ms			  = 20;
		stats.tick_rtt_count			  = 1;
		monitor.tick();
		CHECK(monitor.baseline_.ticks == 1 && monitor.baseline_.rtt_samples == 1);
		CHECK(monitor.profile_stats_.size() == 1 && monitor.profile_stats_[0].activations == 0 &&
			  monitor.profile_stats_[0].active.ticks == 0);
	}

	engine.setup(1);
	CHECK(engine.is_running(1));
	for (int second = 0; second < 2; ++second)
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		auto&						stats = monitor.servers_[kServerAddress];
		stats.tick_rtt_sum_ms			  = 100;
		stats.tick_rtt_count			  = 1;
		stats.data_up += 50;
		stats.retrans_up += 5;
		stats.down.bytes_tick = 1000;
		monitor.tick();
	}
	{
		std::lock_guard<std::mutex>		lock(monitor.mutex_);
		const NetMonitor::ProfileStats& profile = monitor.profile_stats_[0];
		CHECK(profile.activations == 1 && profile.current_ticks == 2 && profile.active.ticks == 2);
		CHECK(profile.active.rtt_samples == 2 && profile.active.data_packets == 100 && profile.active.retransmits == 10 &&
			  profile.active.bytes_down == 2000);
		CHECK(monitor.baseline_.ticks == 1);
	}

	engine.teardown(1);
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		monitor.tick();
		const NetMonitor::ProfileStats& profile = monitor.profile_stats_[0];
		CHECK(profile.current_ticks == 0 && profile.last_ticks == 2 && profile.longest_ticks == 2 && profile.active.ticks == 2);
		CHECK(monitor.baseline_.ticks == 2);
	}

	CHECK(monitor.handle_key('p'));
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		CHECK(monitor.view_ == NetMonitor::View::profiles);
		const std::string frame = monitor.render_profile_view(120, 30);
		CHECK(frame.find("Profile activity") != std::string::npos && frame.find("Network while active") != std::string::npos);
		CHECK(frame.find("no profile active") != std::string::npos && frame.find("+80 ms") != std::string::npos);
		const auto count_lines = [](const std::string& text) { return std::count(text.begin(), text.end(), '\n'); };
		CHECK(count_lines(frame) <= 29);
	}
	CHECK(monitor.handle_key('p'));
	CHECK(monitor.view_ == NetMonitor::View::overview);

	CHECK(monitor.handle_key('p'));
	CHECK(monitor.handle_key('r'));
	monitor.reset_requested_ = false;
	std::lock_guard<std::mutex> lock(monitor.mutex_);
	monitor.reset_locked();
	CHECK(monitor.profile_stats_.size() == 1 && monitor.profile_stats_[0].activations == 0 && monitor.baseline_.ticks == 0);
}

void test_udp_and_tcp_flows_are_listed()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	feed(monitor, to_server(100, 0, kSyn, 0));
	feed(monitor, from_server(500, 101, kSyn | kAck, 0));
	feed(monitor, ipv4_packet(kUdp, udp_datagram(4000, 3074, 20), kClient, kServer));
	feed(monitor, ipv4_packet(kUdp, udp_datagram(3074, 4000, 100), kServer, kClient));

	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		const auto&					stats = monitor.servers_[kServerAddress];
		CHECK(stats.flows.size() == 2 && stats.flows_opened == 1);
		const auto udp = stats.flows.find((uint64_t{1} << 32) | (4000u << 16) | 3074);
		CHECK(udp != stats.flows.end());
		if (udp != stats.flows.end())
			CHECK(!udp->second.tcp && udp->second.client_port == 4000 && udp->second.server_port == 3074 && udp->second.packets_up == 1 &&
				  udp->second.packets_down == 1 && udp->second.bytes_down > udp->second.bytes_up);
		const auto tcp = stats.flows.find((1000u << 16) | 2000);
		CHECK(tcp != stats.flows.end());
		if (tcp != stats.flows.end())
			CHECK(tcp->second.tcp && tcp->second.packets_up == 1 && tcp->second.packets_down == 1);
	}

	CHECK(monitor.handle_key('f'));
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		CHECK(monitor.view_ == NetMonitor::View::flows && monitor.has_selection_);
		const std::string frame = monitor.render_flow_view(120, 0);
		CHECK(frame.find("Selected flow") != std::string::npos && frame.find("tcp") != std::string::npos &&
			  frame.find("udp") != std::string::npos);
		CHECK(frame.find("connecting") != std::string::npos || frame.find("established") != std::string::npos);
	}
	const uint64_t before = [&] {
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		return monitor.selection_.key;
	}();
	CHECK(monitor.handle_key(platform::key::down));
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		CHECK(monitor.selection_.key != before);
		// Only the selected flow keeps a history.
		monitor.tick();
		int with_history = 0;
		for (const auto& entry : monitor.servers_[kServerAddress].flows)
			with_history += entry.second.detail ? 1 : 0;
		CHECK(with_history == 1);
		CHECK(monitor.render_flow_view(120, 0).find("collecting") == std::string::npos);
	}
	CHECK(monitor.handle_key(platform::key::up));
	CHECK(monitor.handle_key('f'));
	CHECK(monitor.view_ == NetMonitor::View::overview);
	CHECK(!monitor.handle_key('x'));
}

void test_flow_table_is_bounded_and_prefers_closed_flows_for_eviction()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	// The first connection is closed by a reset, so it is the one that has to make room.
	feed(monitor, ipv4_packet(kTcp, tcp_segment(5000, 2000, 1, 1, kRst), kClient, kServer));
	for (uint16_t port = 6000; port < 6000 + 300; ++port)
		feed(monitor, ipv4_packet(kUdp, udp_datagram(port, 3074, 10), kClient, kServer));
	std::lock_guard<std::mutex> lock(monitor.mutex_);
	const auto&					stats = monitor.servers_[kServerAddress];
	CHECK(stats.flows.size() == 256);
	CHECK(stats.flows.count((5000u << 16) | 2000) == 0);
}

void test_rtt_spread_is_recorded_and_drawn()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	engine.cycle_server(1);
	NetMonitor monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	feed(monitor, to_server(100, 1, kAck | kPsh, 10));
	std::this_thread::sleep_for(std::chrono::milliseconds(30));
	feed(monitor, from_server(1, 110, kAck, 0));
	std::lock_guard<std::mutex> lock(monitor.mutex_);
	auto&						stats	= monitor.servers_[kServerAddress];
	uint64_t					samples = 0;
	for (const uint64_t count : stats.rtt_hist)
		samples += count;
	CHECK(samples == 1 && stats.tick_rtt_min_ms >= 25 && stats.tick_rtt_max_ms == stats.tick_rtt_min_ms);
	monitor.tick();
	CHECK(stats.rtt_min.values.size() == 1 && stats.rtt_max.values.size() == 1 && stats.rtt_min.values[0] == stats.rtt_max.values[0]);
	stats.rtt.values.push_back(80);
	stats.rtt_min.values.push_back(20);
	stats.rtt_max.values.push_back(200);
	const std::string frame = monitor.render_frame(140, 120);
	CHECK(frame.find("RTT spread") != std::string::npos);
	CHECK(frame.find("▓") != std::string::npos || frame.find("│") != std::string::npos);
}

void test_gateway_forwarded_traffic_is_requested()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	CHECK(fakes::channel(0)->options.include_forward && fakes::channel(0)->options.sniff);
	monitor.stop();
}

std::filesystem::path scratch_directory(const char* name)
{
	const std::filesystem::path path = std::filesystem::temp_directory_path() / (std::string("lagsw_net_monitor_") + name);
	std::filesystem::remove_all(path);
	return path;
}

std::string read_file(const std::filesystem::path& path)
{
	std::ifstream	   file(path);
	std::ostringstream text;
	text << file.rdbuf();
	return text.str();
}

void test_export_writes_csv_and_json()
{
	fakes::reset();
	const std::filesystem::path directory		  = scratch_directory("export");
	PacketEngineOptions			options			  = options_with_server();
	options.features.net_monitor.export_directory = (directory / "nested").string();
	PacketEngine engine(options);
	NetMonitor	 monitor(engine, options);
	monitor.toggle();
	monitor.stop();

	feed(monitor, to_server(1, 1, kAck | kPsh, 10));
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		monitor.tick();
		monitor.tick();
	}
	CHECK(monitor.handle_key('e'));
	std::string message;
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		message = monitor.status_message_;
	}
	CHECK(message.rfind("exported to ", 0) == 0);

	std::filesystem::path csv, json;
	for (const auto& entry : std::filesystem::directory_iterator(directory / "nested"))
		(entry.path().extension() == ".csv" ? csv : json) = entry.path();
	CHECK(!csv.empty() && !json.empty());
	const std::string csv_text	= read_file(csv);
	const std::string json_text = read_file(json);
	CHECK(csv_text.rfind("second,server,address,", 0) == 0);
	CHECK(csv_text.find("\"Test\",192.168.1.20,") != std::string::npos);
	CHECK(std::count(csv_text.begin(), csv_text.end(), '\n') == 3);	 // the header and one row per second and server
	CHECK(json_text.find("\"address\":\"192.168.1.20\"") != std::string::npos && json_text.find("\"series\"") != std::string::npos);
	CHECK(json_text.find("\"flows\"") != std::string::npos && json_text.find("\"events\"") != std::string::npos);

	// A second export in the same second must not overwrite the first.
	CHECK(monitor.handle_key('E'));
	size_t files = 0;
	for (const auto& entry : std::filesystem::directory_iterator(directory / "nested"))
		files += entry.is_regular_file() ? 1 : 0;
	CHECK(files == 4);
	std::filesystem::remove_all(directory);
}

void test_log_file_keeps_history_after_the_view_closes()
{
	fakes::reset();
	const std::filesystem::path directory = scratch_directory("log");
	PacketEngineOptions			options	  = options_with_server();
	options.features.net_monitor.log_file = (directory / "logs" / "net.jsonl").string();
	PacketEngine engine(options);
	NetMonitor	 monitor(engine, options);
	monitor.toggle();
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		monitor.add_event_locked(NetMonitor::Event::Level::alert, "a \"quoted\" event");
		monitor.tick();
	}
	monitor.stop();

	const std::string text = read_file(directory / "logs" / "net.jsonl");
	CHECK(text.find("net monitor opened") != std::string::npos && text.find("net monitor closed") != std::string::npos);
	CHECK(text.find("\"server\":\"192.168.1.20\"") != std::string::npos);
	CHECK(text.find("\"text\":\"a \\\"quoted\\\" event\"") != std::string::npos);
	std::filesystem::remove_all(directory);
}

#	ifdef LAGSW_FEATURE_SERVER_DISCOVERY
void test_discovered_servers_are_added_and_captured()
{
	fakes::reset();
	PacketEngineOptions options					= options_with_server();
	options.features.server_discovery.enabled	= true;
	options.features.server_discovery.port		= 55000;
	options.features.server_discovery.window_ms = 60000;
	PacketEngine engine(options);
	engine.start_workers();
	const auto discovery = fakes::channel_with_filter("port:55000");
	CHECK(discovery != nullptr);
	if (!discovery)
		return;

	NetMonitor monitor(engine, options);
	monitor.toggle();
	const size_t before = fakes::channels().size();
	const auto	 first	= fakes::channel(before - 1);
	CHECK(first->options.sniff);
	discovery->inject(ipv4_packet(kTcp, tcp_segment(40000, 55000, 1, 1, kAck), kClient, {34, 0, 0, 1}));
	CHECK(wait_until([&] { return engine.servers().size() == 2; }));

	// The render thread notices the new server and reopens the capture with a filter that includes it.
	CHECK(wait_until([&] { return fakes::channels().size() == before + 1; }));
	CHECK(first->closed());
	CHECK(fakes::last_profile_spec().server_addresses.size() == 2);
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		CHECK(monitor.servers_.count("34.0.0.1") == 1 && monitor.server_order_.size() == 2);
		CHECK(!monitor.events_.empty() && monitor.events_.back().text.find("34.0.0.1") != std::string::npos);
	}
	const auto second = fakes::channel(before);
	second->inject(ipv4_packet(kTcp, tcp_segment(1000, 2000, 1, 1, kAck), kClient, {34, 0, 0, 1}), 1, true);
	CHECK(wait_until([&] {
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		return monitor.servers_["34.0.0.1"].up.packets == 1;
	}));
	monitor.stop();
	CHECK(second->closed());
}
#	endif
}  // namespace

int main(int argc, char** argv)
{
	logging::set_level(logging::level::error);
	static const test::TestCase cases[] = {
		{"toggle_key_follows_the_configuration", test_toggle_key_follows_the_configuration},
		{"no_capture_without_servers", test_no_capture_without_servers},
		{"toggle_opens_and_closes_a_sniff_channel", test_toggle_opens_and_closes_a_sniff_channel},
		{"rtt_is_measured_from_data_to_ack", test_rtt_is_measured_from_data_to_ack},
#	ifdef LAGSW_FEATURE_PASSIVE_LATENCY
		{"monitor_and_profile_receive_packets_with_passive_latency", test_monitor_and_profile_receive_packets_with_passive_latency},
#	endif
		{"direction_comes_from_the_server_address_not_the_backend_flag", test_direction_comes_from_the_server_address_not_the_backend_flag},
		{"retransmissions_are_counted_and_not_sampled", test_retransmissions_are_counted_and_not_sampled},
		{"pause_ignores_packets_and_reset_clears_them", test_pause_ignores_packets_and_reset_clears_them},
		{"view_keys_follow_the_configuration", test_view_keys_follow_the_configuration},
		{"charts_and_frame_render", test_charts_and_frame_render},
		{"silent_server_row", test_silent_server_row},
#	if defined(LAGSW_FEATURE_SERVER_DISCOVERY) && defined(LAGSW_FEATURE_REGION_ENFORCEMENT)
		{"probes_do_not_update_silence_or_alerts", test_probes_do_not_update_silence_or_alerts},
#	endif
		{"ports_sizes_and_handshakes", test_ports_sizes_and_handshakes},
		{"tcp_health_flows_and_path", test_tcp_health_flows_and_path},
		{"capture_health_and_warnings", test_capture_health_and_warnings},
		{"one_sided_capture_is_called_out", test_one_sided_capture_is_called_out},
		{"layout_fits_the_console", test_resize_is_not_needed_for_the_layout_to_fit},
		{"alerts_raise_and_clear", test_alerts_raise_and_clear},
		{"alerts_can_be_disabled", test_alerts_can_be_disabled},
		{"profile_changes_become_events_and_markers", test_profile_changes_become_events_and_markers},
		{"profile_view_tracks_activations_and_conditions", test_profile_view_tracks_activations_and_conditions},
		{"udp_and_tcp_flows_are_listed", test_udp_and_tcp_flows_are_listed},
		{"flow_table_is_bounded", test_flow_table_is_bounded_and_prefers_closed_flows_for_eviction},
		{"rtt_spread_is_recorded_and_drawn", test_rtt_spread_is_recorded_and_drawn},
		{"gateway_forwarded_traffic_is_requested", test_gateway_forwarded_traffic_is_requested},
		{"export_writes_csv_and_json", test_export_writes_csv_and_json},
		{"log_file_keeps_history_after_the_view_closes", test_log_file_keeps_history_after_the_view_closes},
#	ifdef LAGSW_FEATURE_SERVER_DISCOVERY
		{"discovered_servers_are_added_and_captured", test_discovered_servers_are_added_and_captured},
#	endif
	};
	return test::run_tests("net_monitor", cases, argc, argv);
}

#else

int main()
{
	std::puts("net_monitor: skipped, feature not compiled in");
	return 0;
}

#endif
