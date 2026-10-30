// Unit tests for PacketEngine (src/packet_engine/): profile lifecycle, packet scheduling through real worker threads, server
// selection and discovery, forwarded-address discovery, region resolution and the state report. The capture backend and the
// platform services are replaced by the in-memory fakes in fakes.cc, see fakes.h.
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "fakes.h"
#include "log.h"
#include "packet_engine.h"
#include "packet_engine_util.h"
#include "support/capture.h"
#include "support/packets.h"
#include "support/test.h"

namespace {
using namespace packets;
using fakes::wait_until;

constexpr uint16_t kDiscoveryPort  = 55000;
constexpr uint64_t kDiscoveryWindowMs = 100;
const std::chrono::milliseconds kWindowPause(kDiscoveryWindowMs + 60);

ProfileOptions profile(const char* name, PacketDelayMode mode = PacketDelayMode::from_timestamp, int32_t delay_ms = 0)
{
	ProfileOptions options;
	options.name	   = name;
	options.delay_mode = mode;
	options.delay_ms   = delay_ms;
	return options;
}

ServerOptions server(const char* address, const char* name = "", const char* group = "")
{
	return {address, *name == '\0' ? address : name, group};
}

PacketEngineOptions engine_options(std::vector<ProfileOptions> profiles, std::vector<ServerOptions> servers = {})
{
	PacketEngineOptions options;
	options.profiles = std::move(profiles);
	options.servers	 = std::move(servers);
	return options;
}

PacketEngineOptions discovery_options(std::vector<ProfileOptions> profiles = {profile("A")}, std::vector<ServerOptions> servers = {})
{
	PacketEngineOptions options = engine_options(std::move(profiles), std::move(servers));
	options.discovery_port		= kDiscoveryPort;
	options.discovery_window_ms = kDiscoveryWindowMs;
	return options;
}

/// A TCP packet addressed to `server` on the discovery port; the discovery logic takes the endpoint on that port as the server.
Bytes to_server(std::array<uint8_t, 4> server_address, uint16_t port = kDiscoveryPort)
{
	return ipv4_packet(kTcp, tcp_segment(40000, port, 1, 1, kAck), {10, 0, 0, 5}, server_address);
}

/// Runs `body` with INFO logging on and returns what was logged, then restores the quiet level the tests normally run at.
std::string logged(const std::function<void()>& body, logging::level level = logging::level::info)
{
	logging::set_level(level);
	const std::string text = test::capture_stdout(body);
	logging::set_level(logging::level::error);
	return text;
}

std::string state_report(const PacketEngine& engine)
{
	return logged([&] { engine.print_state(); });
}

bool report_contains(const PacketEngine& engine, const std::string& text)
{
	return state_report(engine).find(text) != std::string::npos;
}

/// Feeds the discovery channel `counts` packets per server, lets the discovery window run out and closes it with one more packet to
/// the first server (so list the expected winner first).
void run_discovery_window(const std::shared_ptr<fakes::ChannelState>& channel, const std::vector<std::pair<std::array<uint8_t, 4>, int>>& counts)
{
	size_t expected = channel->consumed();
	for (const auto& [address, count] : counts)
		for (int index = 0; index < count; ++index)
		{
			channel->inject(to_server(address));
			++expected;
		}
	wait_until([&] { return channel->consumed() >= expected; });
	std::this_thread::sleep_for(kWindowPause);
	channel->inject(to_server(counts.front().first));
	++expected;
	wait_until([&] { return channel->consumed() >= expected; });
}

void test_initial_server_selection()
{
	fakes::reset();
	const std::vector<ServerOptions> servers = {server("1.1.1.1", "alpha"), server("2.2.2.2", "beta", "EU"), server("3.3.3.3")};
	const auto						 selected = [&](std::optional<std::string> initial) {
		PacketEngineOptions options = engine_options({profile("A")}, servers);
		options.initial_server		= std::move(initial);
		PacketEngine engine(options);
		return engine.current_server();
	};
	CHECK(selected(std::nullopt) == "none");
	CHECK(selected("none") == "none");
	CHECK(selected("1.1.1.1") == "alpha [1.1.1.1]");
	CHECK(selected("alpha") == "alpha [1.1.1.1]");
	CHECK(selected("beta") == "EU: beta [2.2.2.2]");
	CHECK(selected("3.3.3.3") == "3.3.3.3");
	CHECK(selected("missing") == "none");
}

void test_cycle_server_walks_the_list_and_wraps()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A")}, {server("1.1.1.1", "alpha"), server("2.2.2.2", "beta")}));
	CHECK(engine.current_server() == "none");
	engine.cycle_server(1);
	CHECK(engine.current_server() == "alpha [1.1.1.1]");
	engine.cycle_server(1);
	CHECK(engine.current_server() == "beta [2.2.2.2]");
	engine.cycle_server(1);
	CHECK(engine.current_server() == "none");
	engine.cycle_server(-1);
	CHECK(engine.current_server() == "beta [2.2.2.2]");
	engine.cycle_server(-1);
	engine.cycle_server(-1);
	CHECK(engine.current_server() == "none");
	engine.cycle_server(0);
	CHECK(engine.current_server() == "none");

	PacketEngine empty(engine_options({profile("A")}));
	empty.cycle_server(1);
	CHECK(empty.current_server() == "none");
}

void test_setup_and_teardown_manage_the_channel()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A")}));
	CHECK(!engine.is_running() && !engine.is_running(1));

	engine.setup(1);
	CHECK(engine.is_running() && engine.is_running(1));
	CHECK(fakes::channels().size() == 1);
	const auto channel = fakes::channel(0);
	CHECK(channel && channel->filter == "profile#0");
	CHECK(fakes::timer_resolution_begins() == 1);

	engine.setup(1);
	CHECK(fakes::channels().size() == 1 && fakes::timer_resolution_begins() == 1);

	engine.teardown(1);
	CHECK(!engine.is_running() && !engine.is_running(1));
	CHECK(wait_until([&] { return channel->closed() && fakes::timer_resolution_ends() == 1; }));
	engine.teardown(1);
	CHECK(fakes::timer_resolution_ends() == 1);

	engine.setup(1);
	CHECK(engine.is_running(1) && fakes::channels().size() == 2);
}

void test_unknown_profiles_are_rejected()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A")}));
	const std::string log = logged([&] {
		engine.setup(0);
		engine.setup(2);
	}, logging::level::error);
	CHECK(log.find("Profile 0 is not configured") != std::string::npos && log.find("Profile 2 is not configured") != std::string::npos);
	CHECK(!engine.is_running() && !engine.is_running(0) && !engine.is_running(2) && !engine.is_running(-1));
	CHECK(!engine.toggle(0) && !engine.toggle(2));
	engine.teardown(7);
	engine.flush_on_demand(7);
	CHECK(fakes::channels().empty());
	CHECK(engine.profile_packet_status(0).empty() && engine.profile_packet_status(3).empty());
	CHECK(engine.profile_running_time_ms(0) == 0 && engine.profile_running_time_ms(3) == 0);
}

void test_failing_to_open_a_channel_leaves_the_profile_inactive()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A")}));
	fakes::fail_next_open("no driver");
	const std::string log = logged([&] { engine.setup(1); }, logging::level::error);
	CHECK(log.find("failed to open capture channel: no driver") != std::string::npos);
	CHECK(!engine.is_running() && !engine.is_running(1));
	CHECK(fakes::channels().empty());
	CHECK(fakes::timer_resolution_begins() == fakes::timer_resolution_ends());

	engine.setup(1);
	CHECK(engine.is_running(1));
}

void test_profiles_run_independently()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A"), profile("B")}));
	engine.setup(1);
	engine.setup(2);
	CHECK(engine.is_running(1) && engine.is_running(2) && fakes::channels().size() == 2);
	engine.teardown(1);
	CHECK(!engine.is_running(1) && engine.is_running(2) && engine.is_running());
	engine.teardown();
	CHECK(!engine.is_running(2) && !engine.is_running());
	CHECK(wait_until([&] { return fakes::channel(0)->closed() && fakes::channel(1)->closed(); }));
}

void test_destroying_the_engine_closes_active_channels()
{
	fakes::reset();
	std::shared_ptr<fakes::ChannelState> channel;
	{
		PacketEngine engine(engine_options({profile("A", PacketDelayMode::from_timestamp, 0)}));
		engine.setup(1);
		channel = fakes::channel(0);
		channel->inject(tcp_packet(1, 1), 1);
		CHECK(wait_until([&] { return engine.pending_packets() == 1; }));
	}
	CHECK(channel->closed());
	CHECK(channel->sent_count() == 1);
	CHECK(fakes::timer_resolution_begins() == fakes::timer_resolution_ends());
}

void test_delayed_packets_are_sent_unchanged()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A", PacketDelayMode::from_timestamp, 50)}));
	engine.setup(1);
	const auto	channel = fakes::channel(0);
	const Bytes packet	= tcp_packet(1234, 5678, kAck | kPsh);
	channel->inject(packet, 7, true, 3);
	CHECK(wait_until([&] { return channel->sent_count() == 1; }));
	const auto sent = channel->sent_packets();
	CHECK(sent[0].data == packet);
	CHECK(sent[0].meta.timestamp == 7 && sent[0].meta.outbound && sent[0].meta.if_index == 3);
	CHECK(wait_until([&] { return engine.pending_packets() == 0; }));
	CHECK(channel->discarded().empty());
}

void test_packets_without_a_delay_are_held_until_teardown()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A", PacketDelayMode::from_timestamp, 0)}));
	engine.setup(1);
	const auto channel = fakes::channel(0);
	for (int64_t id = 1; id <= 3; ++id)
		channel->inject(tcp_packet(static_cast<uint32_t>(id), 1), id);
	CHECK(wait_until([&] { return engine.pending_packets() == 3; }));
	CHECK(channel->sent_count() == 0);
	CHECK(engine.next_batch_in_ms() == (std::numeric_limits<uint64_t>::max)());

	engine.teardown(1);
	CHECK(wait_until([&] { return channel->closed(); }));
	const auto sent = channel->sent_packets();
	CHECK(sent.size() == 3);
	for (size_t index = 0; index < sent.size(); ++index)
		CHECK(sent[index].meta.timestamp == static_cast<int64_t>(index + 1));
	CHECK(engine.pending_packets() == 0 && engine.next_batch_in_ms() == 0);
}

void test_next_batch_counts_down_to_the_release_time()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A", PacketDelayMode::from_timestamp, 60000)}));
	engine.setup(1);
	CHECK(engine.next_batch_in_ms() == 0);
	fakes::channel(0)->inject(tcp_packet(1, 1), 1);
	CHECK(wait_until([&] { return engine.pending_packets() == 1; }));
	const uint64_t next = engine.next_batch_in_ms();
	CHECK(next > 50000 && next <= 60000);
}

void test_sniffing_profiles_do_not_touch_packets()
{
	fakes::reset();
	ProfileOptions sniffer			= profile("A", PacketDelayMode::from_timestamp, 1);
	sniffer.capture_options.sniff	= true;
	sniffer.capture_options.forward = true;
	PacketEngine engine(engine_options({sniffer}));
	engine.setup(1);
	const auto channel = fakes::channel(0);
	CHECK(channel->options.sniff && channel->options.forward && !channel->options.include_forward);
	channel->inject(tcp_packet(1, 1), 1);
	channel->inject(tcp_packet(2, 1), 2);
	CHECK(wait_until([&] { return channel->consumed() == 2; }));
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	CHECK(engine.pending_packets() == 0 && channel->sent_count() == 0 && channel->discarded().empty());
	CHECK(report_contains(engine, "packets caught:  " + highlight("2")));
}

void test_non_sniffing_profiles_open_a_plain_channel()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A")}));
	engine.setup(1);
	const auto channel = fakes::channel(0);
	CHECK(!channel->options.sniff && !channel->options.forward && !channel->options.include_forward);
}

void test_dropped_packets_are_reported_to_the_backend()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A", PacketDelayMode::drop)}));
	engine.setup(1);
	const auto channel = fakes::channel(0);
	channel->inject(tcp_packet(1, 1), 11);
	channel->inject(tcp_packet(2, 1), 12);
	CHECK(wait_until([&] { return channel->discarded().size() == 2; }));
	CHECK((channel->discarded() == std::vector<int64_t>{11, 12}));
	CHECK(channel->sent_count() == 0 && engine.pending_packets() == 0);
}

void test_failed_sends_are_logged_and_not_retried()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A", PacketDelayMode::from_timestamp, 1)}));
	engine.setup(1);
	const auto channel = fakes::channel(0);
	channel->fail_sends(true);
	const std::string log = logged([&] {
		channel->inject(tcp_packet(1, 1), 1);
		wait_until([&] { return channel->consumed() == 1 && engine.pending_packets() == 0; });
		std::this_thread::sleep_for(std::chrono::milliseconds(300));
	}, logging::level::error);
	CHECK(log.find("send: failed: send failed (fake)") != std::string::npos);
	CHECK(channel->sent_count() == 0);
}

void test_toggle_releases_held_packets()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A", PacketDelayMode::hold_until_deactivation)}));
	CHECK(!engine.toggle(1));
	engine.setup(1);
	const auto channel = fakes::channel(0);
	channel->inject(tcp_packet(1, 1), 1);
	channel->inject(tcp_packet(2, 1), 2);
	CHECK(wait_until([&] { return engine.pending_packets() == 2; }));
	CHECK(channel->sent_count() == 0);
	CHECK(engine.toggle(1));
	CHECK(wait_until([&] { return channel->sent_count() == 2; }));
	CHECK(engine.is_running(1));
}

void test_flush_on_demand_releases_an_amount()
{
	fakes::reset();
	ProfileOptions options = profile("A", PacketDelayMode::hold_until_deactivation);
	options.amount		   = 1;
	PacketEngine engine(engine_options({options}));
	engine.flush_on_demand(1);
	engine.setup(1);
	const auto channel = fakes::channel(0);
	for (int64_t id = 1; id <= 3; ++id)
		channel->inject(tcp_packet(static_cast<uint32_t>(id), 1), id);
	CHECK(wait_until([&] { return engine.pending_packets() == 3; }));
	engine.flush_on_demand(1);
	CHECK(wait_until([&] { return channel->sent_count() == 1 && engine.pending_packets() == 2; }));
	CHECK(channel->sent_packets()[0].meta.timestamp == 1);
}

void test_packet_mode_status_is_reported_while_active()
{
	fakes::reset();
	ProfileOptions options = profile("A", PacketDelayMode::packet_group_send);
	options.group_count	   = 2;
	PacketEngine engine(engine_options({options}));
	CHECK(engine.profile_packet_status(1).empty());
	engine.setup(1);
	CHECK(engine.profile_packet_status(1) == "Capturing group 1/2");
	CHECK(!engine.toggle(1));
	CHECK(engine.profile_packet_status(1) == "Capturing group 2/2");
	engine.teardown(1);
	CHECK(engine.profile_packet_status(1).empty());
}

void test_capture_filters_describe_the_selected_server()
{
	fakes::reset();
	ProfileOptions tracking					 = profile("A");
	tracking.capture_options.server_direction = backend::ServerDirection::source;
	PacketEngineOptions options				 = engine_options({tracking}, {server("34.0.0.1", "A1", "EU"), server("34.0.0.2", "A2", "EU"), server("35.0.0.1", "B1"), server("35.0.0.2", "B2")});
	options.initial_server					 = "A1";
	PacketEngine engine(options);

	const auto expect_spec = [&](size_t index, std::vector<std::string> addresses) {
		const auto specs = fakes::profile_specs();
		CHECK(specs.size() > index);
		if (specs.size() <= index)
			return;
		CHECK(specs[index].server_addresses == addresses);
		CHECK(specs[index].server_direction == std::optional<backend::ServerDirection>(addresses.empty() ? std::nullopt : std::optional<backend::ServerDirection>(backend::ServerDirection::source)));
	};
	engine.setup(1);
	expect_spec(0, {"34.0.0.1", "34.0.0.2"});
	engine.cycle_server(1);  // another member of the same group
	expect_spec(1, {"34.0.0.1", "34.0.0.2"});
	engine.cycle_server(1);  // an ungrouped server is matched on its own
	expect_spec(2, {"35.0.0.1"});
	engine.cycle_server(1);
	expect_spec(3, {"35.0.0.2"});
	engine.cycle_server(1);  // wraps to "none": no server restriction at all
	expect_spec(4, {});
	CHECK(engine.is_running(1));
	CHECK(wait_until([&] { return fakes::channels().size() == 5 && fakes::channel(3)->closed(); }));
}

void test_capture_filters_without_a_server_direction_ignore_the_server()
{
	fakes::reset();
	PacketEngineOptions options = engine_options({profile("A")}, {server("34.0.0.1")});
	options.initial_server		= "34.0.0.1";
	PacketEngine engine(options);
	engine.setup(1);
	const auto spec = fakes::last_profile_spec();
	CHECK(spec.server_addresses.empty() && !spec.server_direction);
}

void test_cycling_servers_restarts_active_profiles_only()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A"), profile("B")}, {server("1.1.1.1"), server("2.2.2.2")}));
	engine.setup(2);
	engine.cycle_server(1);
	CHECK(!engine.is_running(1) && engine.is_running(2));
	CHECK(fakes::channels().size() == 2);
	CHECK(wait_until([&] { return fakes::channel(0)->closed(); }));
	CHECK(!fakes::channel(1)->closed());
}

void test_capture_filters_carry_the_profile_settings()
{
	fakes::reset();
	ProfileOptions first = profile("A");
	first.capture_options.client_address_enforcement = backend::ClientAddressEnforcement::source;
	first.capture_options.outbound					 = true;
	first.ack_restoration							 = true;
	ProfileOptions second							 = profile("B");
	second.filter									 = "udp";
	PacketEngineOptions options						 = engine_options({first, second});
	options.global_filter							 = "tcp";
	options.client_source_address					 = "10.1.1.1";
	options.client_destination_address				 = "10.2.2.2";
	PacketEngine engine(options);
	engine.setup(1);
	engine.setup(2);
	const auto specs = fakes::profile_specs();
	CHECK(specs.size() == 2);
	if (specs.size() != 2)
		return;
	CHECK(specs[0].user_filter == "tcp" && specs[1].user_filter == "udp");
	CHECK(specs[0].client_enforcement == backend::ClientAddressEnforcement::source);
	CHECK(specs[1].client_enforcement == backend::ClientAddressEnforcement::both);
	CHECK(specs[0].outbound && !specs[1].outbound);
	CHECK(specs[0].include_bare_acks && !specs[1].include_bare_acks);
	CHECK(specs[0].client_source == std::optional<std::string>("10.1.1.1") && specs[0].client_destination == std::optional<std::string>("10.2.2.2"));
}

void test_running_times_follow_activations()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A")}));
	CHECK(engine.running_time_ms() == 0 && engine.profile_running_time_ms(1) == 0);
	engine.setup(1);
	CHECK(wait_until([&] { return engine.profile_running_time_ms(1) >= 30 && engine.running_time_ms() >= 30; }));
	engine.teardown(1);
	CHECK(engine.running_time_ms() == 0 && engine.profile_running_time_ms(1) == 0);
}

#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
void test_desync_countdown_follows_the_last_activation()
{
	fakes::reset();
	PacketEngineOptions options					   = engine_options({profile("A")});
	options.features.desync_countdown.enabled		   = true;
	options.features.desync_countdown.duration_percent = 100;
	PacketEngine engine(options);
	CHECK(!engine.profile_desync_countdown_ms(1) && !engine.profile_desync_countdown_ms(0) && !engine.profile_desync_countdown_ms(2));

	engine.setup(1);
	CHECK(wait_until([&] { return engine.profile_running_time_ms(1) >= 300; }));
	engine.teardown(1);
	const std::optional<uint64_t> countdown = engine.profile_desync_countdown_ms(1);
	CHECK(countdown && *countdown > 0);
}

void test_desync_countdown_expires()
{
	fakes::reset();
	PacketEngineOptions options					   = engine_options({profile("A")});
	options.features.desync_countdown.enabled		   = true;
	options.features.desync_countdown.duration_percent = 50;
	PacketEngine engine(options);
	engine.setup(1);
	CHECK(wait_until([&] { return engine.profile_running_time_ms(1) >= 200; }));
	engine.teardown(1);
	CHECK(engine.profile_desync_countdown_ms(1).has_value());
	CHECK(wait_until([&] { return !engine.profile_desync_countdown_ms(1).has_value(); }));
}

void test_desync_countdown_can_hide_while_active()
{
	fakes::reset();
	PacketEngineOptions options					   = engine_options({profile("A")});
	options.features.desync_countdown.enabled		   = true;
	options.features.desync_countdown.duration_percent = 100;
	options.features.desync_countdown.display		   = DesyncCountdownDisplay::until_reactivated;
	PacketEngine engine(options);
	engine.setup(1);
	CHECK(wait_until([&] { return engine.profile_running_time_ms(1) >= 200; }));
	engine.teardown(1);
	CHECK(engine.profile_desync_countdown_ms(1).has_value());
	engine.setup(1);
	CHECK(!engine.profile_desync_countdown_ms(1).has_value());
}
#endif

void test_discovery_selects_the_busiest_server()
{
	fakes::reset();
	PacketEngine engine(discovery_options());
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("port:55000");
	CHECK(channel != nullptr);
	if (!channel)
		return;
	CHECK(channel->options.sniff && channel->options.include_forward);
	CHECK(!engine.is_authoritative_server());

	run_discovery_window(channel, {{{34, 0, 0, 1}, 3}, {{34, 0, 0, 2}, 1}});
	CHECK(wait_until([&] { return engine.current_server() == "34.0.0.1" && engine.is_authoritative_server(); }));

	// The authoritative server keeps following the busiest one.
	run_discovery_window(channel, {{{34, 0, 0, 2}, 4}, {{34, 0, 0, 1}, 1}});
	CHECK(wait_until([&] { return engine.current_server() == "34.0.0.2"; }));
	CHECK(engine.is_authoritative_server());
}

void test_discovery_understands_which_endpoint_is_the_server()
{
	fakes::reset();
	PacketEngine engine(discovery_options());
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("port:55000");
	if (!channel)
		return;
	// Traffic coming back from the server: the server is the source.
	const Bytes from_server = ipv4_packet(kTcp, tcp_segment(kDiscoveryPort, 40000, 1, 1, kAck), {34, 0, 0, 9}, {10, 0, 0, 5});
	for (int index = 0; index < 3; ++index)
		channel->inject(from_server);
	// No port tells them apart: the direction decides.
	channel->inject(ipv4_packet(kUdp, udp_datagram(kDiscoveryPort, kDiscoveryPort, 4), {10, 0, 0, 5}, {34, 0, 0, 8}), 0, true);
	// Garbage is skipped.
	channel->inject({0x90, 1, 2, 3});
	wait_until([&] { return channel->consumed() == 5; });
	std::this_thread::sleep_for(kWindowPause);
	channel->inject(from_server);
	CHECK(wait_until([&] { return engine.current_server() == "34.0.0.9"; }));
}

void test_discovery_does_not_override_an_initial_server()
{
	fakes::reset();
	PacketEngineOptions options = discovery_options({profile("A")}, {server("9.9.9.9", "chosen")});
	options.initial_server		= "chosen";
	PacketEngine engine(options);
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("port:55000");
	if (!channel)
		return;
	run_discovery_window(channel, {{{34, 0, 0, 1}, 3}});
	CHECK(wait_until([&] { return report_contains(engine, "authoritative:   " + highlight("34.0.0.1") + " (observed)"); }));
	CHECK(engine.current_server() == "chosen [9.9.9.9]" && !engine.is_authoritative_server());
}

void test_discovery_stops_following_after_a_manual_selection()
{
	fakes::reset();
	PacketEngine engine(discovery_options({profile("A")}, {server("1.1.1.1")}));
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("port:55000");
	if (!channel)
		return;
	run_discovery_window(channel, {{{34, 0, 0, 1}, 3}});
	CHECK(wait_until([&] { return engine.current_server() == "34.0.0.1" && engine.is_authoritative_server(); }));

	engine.cycle_server(-1);
	CHECK(!engine.is_authoritative_server() && engine.current_server() == "1.1.1.1");
	run_discovery_window(channel, {{{34, 0, 0, 7}, 3}});
	CHECK(wait_until([&] { return report_contains(engine, "authoritative:   " + highlight("34.0.0.7") + " (observed)"); }));
	CHECK(engine.current_server() == "1.1.1.1");
}

void test_discovery_pauses_while_a_profile_is_active()
{
	fakes::reset();
	PacketEngine engine(discovery_options());
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("port:55000");
	if (!channel)
		return;
	engine.setup(1);
	run_discovery_window(channel, {{{34, 0, 0, 1}, 3}});
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	CHECK(engine.current_server() == "none" && !engine.is_authoritative_server());
	CHECK(report_contains(engine, "ranked servers:  " + highlight("0")));

	engine.teardown(1);
	run_discovery_window(channel, {{{34, 0, 0, 2}, 3}});
	CHECK(wait_until([&] { return engine.current_server() == "34.0.0.2"; }));
}

void test_stopping_the_workers_closes_the_discovery_channel()
{
	fakes::reset();
	PacketEngine engine(discovery_options());
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("port:55000");
	if (!channel)
		return;
	CHECK(!channel->closed());
	engine.stop_workers();
	CHECK(channel->recv_shut_down() && channel->closed());
}

void test_regions_are_resolved_and_servers_renamed()
{
	fakes::reset();
	fakes::set_http_handler([](const std::string&, const std::string& path) -> platform::HttpResponse {
		if (path == "/34.1.2.19/json/")
			return {200, 0, R"({"region": "Iowa", "region_code": "IA", "country_name": "United States", "country_code": "US", "continent_code": "NA", "longitude": -93.6})"};
		if (path == "/json/")
			return {200, 0, R"({"region": "Berlin", "country_name": "Germany"})"};
		return {404, 0, ""};
	});
	PacketEngineOptions options = discovery_options();
	options.resolve_region		= true;
	PacketEngine engine(options);
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("port:55000");
	if (!channel)
		return;
	CHECK(wait_until([&] { return engine.client_region() == "Berlin, Germany"; }));

	run_discovery_window(channel, {{{34, 1, 2, 19}, 3}, {{10, 9, 9, 9}, 1}});
	CHECK(wait_until([&] { return engine.current_server() == "IA-USC-19 [34.1.2.19]"; }));
	CHECK(engine.current_server_region() == "Iowa, United States");
	// Private addresses have no meaningful region, so they are not looked up.
	for (const std::string& path : fakes::http_requests())
		CHECK(path != "/10.9.9.9/json/");
}

void test_regions_of_configured_servers_keep_their_names()
{
	fakes::reset();
	fakes::set_http_handler([](const std::string&, const std::string& path) -> platform::HttpResponse {
		if (path == "/34.1.2.19/json/")
			return {200, 0, R"({"region": "Iowa", "region_code": "IA", "country_name": "United States", "country_code": "US", "longitude": -93.6})"};
		return {404, 0, ""};
	});
	PacketEngineOptions options = discovery_options({profile("A")}, {server("34.1.2.19", "mine")});
	options.initial_server		= "mine";
	options.resolve_region		= true;
	PacketEngine engine(options);
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("port:55000");
	if (!channel)
		return;
	run_discovery_window(channel, {{{34, 1, 2, 19}, 2}});
	CHECK(wait_until([&] { return engine.current_server_region() == "Iowa, United States"; }));
	CHECK(engine.current_server() == "mine [34.1.2.19]");
}

#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
PacketEngineOptions forwarding_options()
{
	PacketEngineOptions options								   = engine_options({profile("A")});
	options.features.forwarded_address_discovery.enabled		   = true;
	options.features.forwarded_address_discovery.inbound_if_idx  = 5;
	options.features.forwarded_address_discovery.outbound_if_idx = 7;
	options.features.forwarded_address_discovery.port			   = kDiscoveryPort;
	options.features.forwarded_address_discovery.window_ms	   = kDiscoveryWindowMs;
	return options;
}

void test_forwarded_address_discovery_learns_the_client_addresses()
{
	fakes::reset();
	PacketEngine engine(forwarding_options());
	CHECK(engine.is_forwarded_address_discovery_enabled());
	CHECK(engine.forwarded_address_discovery_status() == "src: unknown, dst: unknown");
	engine.setup(1);
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("forwarded:5:7:55000");
	CHECK(channel != nullptr);
	if (!channel)
		return;
	CHECK(channel->options.sniff && channel->options.priority == 1000);

	const auto inbound	= [](std::array<uint8_t, 4> client) { return ipv4_packet(kUdp, udp_datagram(kDiscoveryPort, 40000, 4), {34, 0, 0, 1}, client); };
	const auto outbound = [](std::array<uint8_t, 4> client) { return ipv4_packet(kUdp, udp_datagram(40000, kDiscoveryPort, 4), client, {34, 0, 0, 1}); };
	for (int index = 0; index < 3; ++index)
		channel->inject(inbound({192, 168, 1, 50}), 0, false, 5);
	channel->inject(inbound({192, 168, 1, 51}), 0, false, 5);
	for (int index = 0; index < 2; ++index)
		channel->inject(outbound({10, 5, 5, 5}), 0, true, 7);
	// Packets on other interfaces are ignored, however many there are.
	for (int index = 0; index < 6; ++index)
		channel->inject(outbound({1, 1, 1, 1}), 0, true, 9);
	wait_until([&] { return channel->consumed() == 12; });
	std::this_thread::sleep_for(kWindowPause);
	channel->inject(inbound({192, 168, 1, 50}), 0, false, 5);

	CHECK(wait_until([&] { return engine.forwarded_address_discovery_status() == "src: 10.5.5.5, dst: 192.168.1.50"; }));
	// The running profile was restarted with the learned addresses.
	CHECK(wait_until([&] {
		const auto spec = fakes::last_profile_spec();
		return engine.is_running(1) && spec.client_destination == std::optional<std::string>("192.168.1.50") &&
			   spec.client_source == std::optional<std::string>("10.5.5.5");
	}));
}

void test_forwarded_address_discovery_is_off_unless_enabled()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A")}));
	CHECK(!engine.is_forwarded_address_discovery_enabled() && engine.forwarded_address_discovery_status().empty());
	engine.start_workers();
	CHECK(fakes::channels().empty());
}
#endif

void test_state_report_describes_profiles_and_queues()
{
	fakes::reset();
	PacketEngine engine(engine_options({profile("A", PacketDelayMode::from_timestamp, 0)}));
	CHECK(report_contains(engine, highlight("STOPPED")));

	engine.setup(1);
	const auto channel = fakes::channel(0);
	channel->inject(tcp_packet(1, 1), 1);
	channel->inject(tcp_packet(2, 1), 2);
	CHECK(wait_until([&] { return engine.pending_packets() == 2; }));
	const std::string running = state_report(engine);
	CHECK(running.find(highlight("RUNNING")) != std::string::npos);
	CHECK(running.find(" A (ACTIVE) ") != std::string::npos);
	CHECK(running.find("packets caught:  " + highlight("2")) != std::string::npos);
	CHECK(running.find("queued packets:  " + highlight("2")) != std::string::npos);
	CHECK(running.find("next release:    " + highlight("on profile deactivation")) != std::string::npos);

	engine.teardown(1);
	CHECK(wait_until([&] { return report_contains(engine, "sent at teardown: " + highlight("2")); }));
	const std::string stopped = state_report(engine);
	CHECK(stopped.find(highlight("STOPPED")) != std::string::npos);
	CHECK(stopped.find(" A (held ") != std::string::npos);
	CHECK(stopped.find("across " + highlight("1") + " activations") != std::string::npos);
	CHECK(stopped.find("queued packets:  " + highlight("0")) != std::string::npos);
}
}  // namespace

int main(int argc, char** argv)
{
	logging::set_level(logging::level::error);
	static const test::TestCase cases[] = {
		{"initial_server_selection", test_initial_server_selection},
		{"cycle_server_walks_the_list_and_wraps", test_cycle_server_walks_the_list_and_wraps},
		{"setup_and_teardown_manage_the_channel", test_setup_and_teardown_manage_the_channel},
		{"unknown_profiles_are_rejected", test_unknown_profiles_are_rejected},
		{"failing_to_open_a_channel_leaves_the_profile_inactive", test_failing_to_open_a_channel_leaves_the_profile_inactive},
		{"profiles_run_independently", test_profiles_run_independently},
		{"destroying_the_engine_closes_active_channels", test_destroying_the_engine_closes_active_channels},
		{"delayed_packets_are_sent_unchanged", test_delayed_packets_are_sent_unchanged},
		{"packets_without_a_delay_are_held_until_teardown", test_packets_without_a_delay_are_held_until_teardown},
		{"next_batch_counts_down_to_the_release_time", test_next_batch_counts_down_to_the_release_time},
		{"sniffing_profiles_do_not_touch_packets", test_sniffing_profiles_do_not_touch_packets},
		{"non_sniffing_profiles_open_a_plain_channel", test_non_sniffing_profiles_open_a_plain_channel},
		{"dropped_packets_are_reported_to_the_backend", test_dropped_packets_are_reported_to_the_backend},
		{"failed_sends_are_logged_and_not_retried", test_failed_sends_are_logged_and_not_retried},
		{"toggle_releases_held_packets", test_toggle_releases_held_packets},
		{"flush_on_demand_releases_an_amount", test_flush_on_demand_releases_an_amount},
		{"packet_mode_status_is_reported_while_active", test_packet_mode_status_is_reported_while_active},
		{"capture_filters_describe_the_selected_server", test_capture_filters_describe_the_selected_server},
		{"capture_filters_without_a_server_direction_ignore_the_server", test_capture_filters_without_a_server_direction_ignore_the_server},
		{"cycling_servers_restarts_active_profiles_only", test_cycling_servers_restarts_active_profiles_only},
		{"capture_filters_carry_the_profile_settings", test_capture_filters_carry_the_profile_settings},
		{"running_times_follow_activations", test_running_times_follow_activations},
#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
		{"desync_countdown_follows_the_last_activation", test_desync_countdown_follows_the_last_activation},
		{"desync_countdown_expires", test_desync_countdown_expires},
		{"desync_countdown_can_hide_while_active", test_desync_countdown_can_hide_while_active},
#endif
		{"discovery_selects_the_busiest_server", test_discovery_selects_the_busiest_server},
		{"discovery_understands_which_endpoint_is_the_server", test_discovery_understands_which_endpoint_is_the_server},
		{"discovery_does_not_override_an_initial_server", test_discovery_does_not_override_an_initial_server},
		{"discovery_stops_following_after_a_manual_selection", test_discovery_stops_following_after_a_manual_selection},
		{"discovery_pauses_while_a_profile_is_active", test_discovery_pauses_while_a_profile_is_active},
		{"stopping_the_workers_closes_the_discovery_channel", test_stopping_the_workers_closes_the_discovery_channel},
		{"regions_are_resolved_and_servers_renamed", test_regions_are_resolved_and_servers_renamed},
		{"regions_of_configured_servers_keep_their_names", test_regions_of_configured_servers_keep_their_names},
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
		{"forwarded_address_discovery_learns_the_client_addresses", test_forwarded_address_discovery_learns_the_client_addresses},
		{"forwarded_address_discovery_is_off_unless_enabled", test_forwarded_address_discovery_is_off_unless_enabled},
#endif
		{"state_report_describes_profiles_and_queues", test_state_report_describes_profiles_and_queues},
	};
	return test::run_tests("engine", cases, argc, argv);
}
