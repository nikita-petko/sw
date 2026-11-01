// Unit tests for the net monitor (src/net_monitor/): capture setup, passive RTT and retransmission measurement, pausing and
// rendering. The monitor runs against the in-memory backend from tests/engine.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef LAGSW_FEATURE_NET_MONITOR

#include "fakes.h"
#include "log.h"
#include "packet_engine.h"
#include "support/packets.h"
#include "support/test.h"

// The tests look at the measured values directly instead of parsing the rendered screen.
#define private public
#include "net_monitor.h"
#undef private

namespace {
using namespace packets;
using fakes::wait_until;

constexpr std::array<uint8_t, 4> kServer = {192, 168, 1, 20};
constexpr std::array<uint8_t, 4> kClient = {10, 0, 0, 1};
const char*						 kServerAddress = "192.168.1.20";

PacketEngineOptions options_with_server()
{
	PacketEngineOptions options;
	ProfileOptions		profile;
	profile.name		  = "A";
	options.profiles	  = {profile};
	options.global_filter = "tcp";
	options.features.net_monitor.enabled = true;
	ServerOptions server;
	server.address = kServerAddress;
	server.name	   = "Test";
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
	PacketEngineOptions options = options_with_server();
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

void test_charts_and_frame_render()
{
	fakes::reset();
	const PacketEngineOptions options = options_with_server();
	PacketEngine			  engine(options);
	engine.cycle_server(1);
	NetMonitor				  monitor(engine, options);
	monitor.toggle();
	monitor.stop();
	{
		std::lock_guard<std::mutex> lock(monitor.mutex_);
		auto&						stats = monitor.servers_[kServerAddress];
		stats.up.packets_tick   = 5;
		stats.down.packets_tick = 50;
		stats.rtt_samples		= 1;
		stats.last_rtt_ms		= 42;
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
		const auto count_lines = [](const std::string& text) { return std::count(text.begin(), text.end(), '\n'); };
		const std::string small = monitor.render_frame(100, 0);
		const std::string tall	= monitor.render_frame(200, 100);
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
	NetMonitor				  monitor(engine, options);
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
	CHECK(monitor.cpu_.values.empty());  // the first sample only sets the baseline
}
}  // namespace

int main(int argc, char** argv)
{
	logging::set_level(logging::level::error);
	static const test::TestCase cases[] = {
		{"toggle_key_follows_the_configuration", test_toggle_key_follows_the_configuration},
		{"no_capture_without_servers", test_no_capture_without_servers},
		{"toggle_opens_and_closes_a_sniff_channel", test_toggle_opens_and_closes_a_sniff_channel},
		{"rtt_is_measured_from_data_to_ack", test_rtt_is_measured_from_data_to_ack},
		{"direction_comes_from_the_server_address_not_the_backend_flag", test_direction_comes_from_the_server_address_not_the_backend_flag},
		{"retransmissions_are_counted_and_not_sampled", test_retransmissions_are_counted_and_not_sampled},
		{"pause_ignores_packets_and_reset_clears_them", test_pause_ignores_packets_and_reset_clears_them},
		{"charts_and_frame_render", test_charts_and_frame_render},
		{"ports_sizes_and_handshakes", test_ports_sizes_and_handshakes},
		{"tcp_health_flows_and_path", test_tcp_health_flows_and_path},
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
