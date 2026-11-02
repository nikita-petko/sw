// Unit tests for passive latency (src/packet_engine/passive_latency.cc): channel setup, the delayed release path,
// overflow fail-open, teardown flushing, and ordering. The engine runs against the in-memory backend from tests/engine.
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include "support/test.h"

#ifdef LAGSW_FEATURE_PASSIVE_LATENCY

#	include "fakes.h"
#	include "log.h"
#	include "packet_engine.h"
#	include "support/capture.h"
#	include "support/packets.h"

namespace {
using namespace packets;
using fakes::wait_until;

ProfileOptions profile(const char* name)
{
	ProfileOptions options;
	options.name = name;
	return options;
}

/// An engine configuration with passive latency on and a single profile (the engine requires at least one).
PacketEngineOptions passive_options(int32_t delay_ms, int32_t max_delay_ms = 0, bool enabled = true)
{
	PacketEngineOptions options;
	options.profiles							  = {profile("A")};
	options.global_filter						  = "tcp";
	options.features.passive_latency.enabled	  = enabled;
	options.features.passive_latency.delay_ms	  = delay_ms;
	options.features.passive_latency.max_delay_ms = max_delay_ms;
	return options;
}

void test_disabled_passive_latency_opens_nothing()
{
	fakes::reset();
	PacketEngine engine(passive_options(50, 0, false));
	engine.start_workers();
	CHECK(fakes::channels().empty());
	CHECK(!engine.is_passive_latency_enabled());
	engine.stop_workers();
}

void test_starting_the_workers_opens_the_passive_channel()
{
	fakes::reset();
	PacketEngine engine(passive_options(50));
	engine.start_workers();
	CHECK(engine.is_passive_latency_enabled());
	const auto channel = fakes::channel_with_filter("tcp");
	CHECK(channel != nullptr);
	CHECK(channel->options.priority == 100);
	engine.stop_workers();
}

void test_custom_filter_overrides_global_filter()
{
	fakes::reset();
	PacketEngineOptions options				= passive_options(50);
	options.features.passive_latency.filter = "udp";
	PacketEngine engine(options);
	engine.start_workers();
	CHECK(fakes::channel_with_filter("udp") != nullptr);
	CHECK(fakes::channel_with_filter("tcp") == nullptr);
	engine.stop_workers();
}

void test_delayed_packets_are_released_after_about_the_configured_delay()
{
	fakes::reset();
	PacketEngine engine(passive_options(200));
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");

	channel->inject(tcp_packet(1, 1, kAck), 1);
	CHECK(wait_until([&] { return channel->consumed() == 1; }));
	CHECK(channel->sent_count() == 0);

	const auto injected = std::chrono::steady_clock::now();
	CHECK(wait_until([&] { return channel->sent_count() == 1; }, std::chrono::milliseconds(2000)));
	const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - injected).count();
	CHECK(elapsed >= 150 && elapsed <= 1000);

	engine.stop_workers();
}

void test_order_is_preserved_for_equal_delays()
{
	fakes::reset();
	PacketEngine engine(passive_options(80));
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");

	channel->inject(tcp_packet(1, 1, kAck), 1);
	channel->inject(tcp_packet(2, 1, kAck), 2);
	channel->inject(tcp_packet(3, 1, kAck), 3);
	CHECK(wait_until([&] { return channel->sent_count() == 3; }, std::chrono::milliseconds(2000)));

	const auto sent = channel->sent_packets();
	CHECK(sent.size() == 3);
	CHECK(sent[0].meta.timestamp == 1 && sent[1].meta.timestamp == 2 && sent[2].meta.timestamp == 3);

	engine.stop_workers();
}

void test_overflow_releases_packets_immediately()
{
	fakes::reset();
	PacketEngineOptions options							= passive_options(5000);
	options.features.passive_latency.max_queued_packets = 1;
	PacketEngine engine(options);
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");

	channel->inject(tcp_packet(1, 1, kAck), 1);
	CHECK(wait_until([&] { return channel->consumed() == 1; }));
	// Give the recv thread time to queue the first packet before the second arrives and overflows it.
	channel->inject(tcp_packet(2, 1, kAck), 2);
	CHECK(wait_until([&] { return channel->sent_count() >= 1; }, std::chrono::milliseconds(2000)));

	engine.stop_workers();
}

void test_stopping_the_workers_flushes_and_closes_the_channel()
{
	fakes::reset();
	PacketEngine engine(passive_options(5000));
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");

	channel->inject(tcp_packet(1, 1, kAck), 1);
	channel->inject(tcp_packet(2, 1, kAck), 2);
	CHECK(wait_until([&] { return channel->consumed() == 2; }));

	engine.stop_workers();
	CHECK(channel->sent_count() == 2);
	CHECK(channel->closed());
}

void test_passive_channel_is_distinct_from_profile_channels()
{
	fakes::reset();
	// Profiles default to toggle activation, so no profile channel opens here; the passive channel must still be its own,
	// separately-filtered channel rather than reusing or aliasing a profile's "profile#<index>" filter.
	PacketEngine engine(passive_options(50));
	engine.start_workers();
	const auto passive = fakes::channel_with_filter("tcp");
	CHECK(passive != nullptr);
	CHECK(fakes::channel_with_filter("profile#0") == nullptr);
	engine.stop_workers();
}

void test_inbound_only_leaves_outbound_packets_undelayed()
{
	fakes::reset();
	PacketEngineOptions options				   = passive_options(5000);
	options.features.passive_latency.direction = PassiveLatencyDirection::inbound;
	PacketEngine engine(options);
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");

	channel->inject(tcp_packet(1, 1, kAck), 1, true);  // outbound: passes through at once
	CHECK(wait_until([&] { return channel->sent_count() == 1; }, std::chrono::milliseconds(1000)));
	channel->inject(tcp_packet(2, 1, kAck), 2, false);	// inbound: held
	CHECK(wait_until([&] { return channel->consumed() == 2; }));
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	CHECK(channel->sent_count() == 1);

	engine.stop_workers();
	CHECK(channel->sent_count() == 2);
}

void test_per_direction_overrides()
{
	fakes::reset();
	PacketEngineOptions options						   = passive_options(5000);
	options.features.passive_latency.outbound_delay_ms = 0;
	options.features.passive_latency.inbound_delay_ms  = 5000;
	PacketEngine engine(options);
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");

	channel->inject(tcp_packet(1, 1, kAck), 1, true);
	CHECK(wait_until([&] { return channel->sent_count() == 1; }, std::chrono::milliseconds(1000)));
	engine.stop_workers();
}

void test_jitter_modes_preserve_order()
{
	for (const PassiveLatencyMode mode : {PassiveLatencyMode::uniform, PassiveLatencyMode::normal})
	{
		fakes::reset();
		PacketEngineOptions options				   = passive_options(60);
		options.features.passive_latency.mode	   = mode;
		options.features.passive_latency.jitter_ms = 50;
		PacketEngine engine(options);
		engine.start_workers();
		const auto channel = fakes::channel_with_filter("tcp");

		for (int64_t id = 1; id <= 20; ++id)
			channel->inject(tcp_packet(static_cast<uint32_t>(id), 1, kAck), id, true);
		CHECK(wait_until([&] { return channel->sent_count() == 20; }, std::chrono::milliseconds(3000)));
		const auto sent = channel->sent_packets();
		for (size_t i = 0; i < sent.size(); ++i)
			CHECK(sent[i].meta.timestamp == static_cast<int64_t>(i + 1));
		engine.stop_workers();
	}
}

void test_status_text()
{
	PacketEngineOptions options = passive_options(60);
	CHECK(PacketEngine(options).passive_latency_status() == "60ms (both)");

	options.features.passive_latency.mode	   = PassiveLatencyMode::uniform;
	options.features.passive_latency.jitter_ms = 10;
	CHECK(PacketEngine(options).passive_latency_status() == "60ms+/-10 (both)");

	options.features.passive_latency.direction = PassiveLatencyDirection::outbound;
	CHECK(PacketEngine(options).passive_latency_status() == "60ms+/-10 out");

	options.features.passive_latency.direction		  = PassiveLatencyDirection::both;
	options.features.passive_latency.inbound_delay_ms = 20;
	CHECK(PacketEngine(options).passive_latency_status() == "60ms+/-10 out, 20ms+/-10 in");
}

void test_pause_flushes_and_lets_packets_through()
{
	fakes::reset();
	PacketEngineOptions options				   = passive_options(5000);
	options.features.passive_latency.pause_key = 'P';
	PacketEngine engine(options);
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");

	channel->inject(tcp_packet(1, 1, kAck), 1);
	CHECK(wait_until([&] { return channel->consumed() == 1; }));
	CHECK(channel->sent_count() == 0);
	CHECK(engine.passive_latency_status() != "paused");

	engine.toggle_passive_latency_pause();	// pausing releases what is queued
	CHECK(engine.is_passive_latency_paused() && engine.passive_latency_status() == "paused");
	CHECK(channel->sent_count() == 1);
	channel->inject(tcp_packet(2, 1, kAck), 2);	 // and new packets are not delayed
	CHECK(wait_until([&] { return channel->sent_count() == 2; }, std::chrono::milliseconds(1000)));

	engine.toggle_passive_latency_pause();	// resuming delays again
	CHECK(!engine.is_passive_latency_paused());
	channel->inject(tcp_packet(3, 1, kAck), 3);
	CHECK(wait_until([&] { return channel->consumed() == 3; }));
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	CHECK(channel->sent_count() == 2);
	engine.stop_workers();
	CHECK(channel->sent_count() == 3);
}

#	ifndef NDEBUG
void test_packet_group_logs_each_packet()
{
	fakes::reset();
	std::string error;
	CHECK(logging::set_groups("+passive_latency.packet", error));
	logging::set_level(logging::level::debug);
	const std::string text = test::capture_stdout([] {
		PacketEngine engine(passive_options(40));
		engine.start_workers();
		const auto channel = fakes::channel_with_filter("tcp");
		channel->inject(tcp_packet(1, 1, kAck), 1, true);
		wait_until([&] { return channel->sent_count() == 1; }, std::chrono::milliseconds(2000));
		engine.stop_workers();
	});
	logging::set_level(logging::level::error);
	CHECK(logging::set_groups("-passive_latency.packet", error));
	CHECK(text.find("Passive latency recv: outbound packet (delaying for 40ms)") != std::string::npos);
	CHECK(text.find("Passive latency send: delayed packet") != std::string::npos);
}
#	endif

// Kernel shaping: the baseline runs in the kernel when the backend allows it and nothing needs the packets in user space.
PacketEngineOptions shaping_passive_options(int32_t delay_ms)
{
	PacketEngineOptions options			  = passive_options(delay_ms);
	options.features.linux_bpf.interfaces = {"lan0"};
	return options;
}

void test_the_baseline_runs_as_a_shaping_stage()
{
	fakes::reset();
	fakes::set_shaping_unavailable("");
	PacketEngineOptions options						= shaping_passive_options(80);
	options.features.passive_latency.mode			= PassiveLatencyMode::uniform;
	options.features.passive_latency.jitter_ms		= 20;
	options.features.passive_latency.direction		= PassiveLatencyDirection::outbound;
	options.features.passive_latency.preserve_order = false;
	PacketEngine engine(options);
	engine.start_workers();
	CHECK(fakes::channels().empty());
	const auto stages = fakes::shape_stages();
	CHECK(stages.size() == 1);
	if (stages.size() == 1)
	{
		const backend::ShapeSpec& spec = stages[0]->spec;
		CHECK(stages[0]->active);
		CHECK(spec.behaviour == backend::ShapeBehaviour::baseline && spec.model == backend::ShapeModel::uniform);
		CHECK(spec.delay_ms == 80 && spec.jitter_ms == 20 && spec.max_delay_ms == 140 && !spec.preserve_order);
		CHECK(spec.include_forward && spec.ignore_inbound && spec.filter == "tcp");
	}
	CHECK(engine.is_passive_latency_enabled());
	engine.stop_workers();
	if (stages.size() == 1)
		CHECK(!stages[0]->active);
}

void test_an_inbound_delay_keeps_the_baseline_in_user_space()
{
	fakes::reset();
	fakes::set_shaping_unavailable("");
	PacketEngine engine(shaping_passive_options(80));  // both directions by default
	engine.start_workers();
	CHECK(fakes::shape_stages().empty());
	CHECK(fakes::channel_with_filter("tcp") != nullptr);
	engine.stop_workers();
}

void test_pausing_the_kernel_baseline_deactivates_the_stage()
{
	fakes::reset();
	fakes::set_shaping_unavailable("");
	PacketEngineOptions options				   = shaping_passive_options(80);
	options.features.passive_latency.direction = PassiveLatencyDirection::outbound;
	PacketEngine engine(options);
	engine.start_workers();
	const auto stages = fakes::shape_stages();
	CHECK(stages.size() == 1);
	engine.toggle_passive_latency_pause();
	CHECK(engine.is_passive_latency_paused() && stages.size() == 1 && !stages[0]->active);
	engine.toggle_passive_latency_pause();
	CHECK(!engine.is_passive_latency_paused() && stages[0]->active && stages[0]->activations == 2);
	engine.stop_workers();
}

void test_the_bpf_tier_does_not_fall_back_for_the_baseline()
{
	fakes::reset();
	fakes::set_shaping_unavailable("no tcx");
	PacketEngineOptions options				   = shaping_passive_options(80);
	options.features.linux_bpf.tier			   = LinuxTier::bpf;
	options.features.passive_latency.direction = PassiveLatencyDirection::outbound;
	PacketEngine	  engine(options);
	const std::string log = test::capture_stdout([&] { engine.start_workers(); });
	CHECK(fakes::channels().empty() && fakes::shape_stages().empty());
	CHECK(log.find("requires kernel shaping") != std::string::npos);
	engine.stop_workers();
}

void test_toggling_without_a_channel_is_harmless()
{
	fakes::reset();
	PacketEngine engine(passive_options(50, 0, false));
	engine.toggle_passive_latency_pause();
	CHECK(!engine.is_passive_latency_paused());
}

#	ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
constexpr uint16_t kProbePort = 55002;

void test_probe_port_traffic_is_not_delayed()
{
	fakes::reset();
	PacketEngineOptions options					   = passive_options(5000);
	options.features.region_enforcement.enabled	   = true;
	options.features.region_enforcement.probe_port = kProbePort;
	PacketEngine engine(options);
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");

	channel->inject(tcp_packet(1, 0, kSyn, 40000, kProbePort), 1, true);		  // probe SYN
	channel->inject(tcp_packet(1, 2, kSyn | kAck, kProbePort, 40000), 2, false);  // answer
	CHECK(wait_until([&] { return channel->sent_count() == 2; }, std::chrono::milliseconds(1000)));
	channel->inject(tcp_packet(3, 1, kAck, 40000, 2000), 3, true);	// game traffic is still held
	CHECK(wait_until([&] { return channel->consumed() == 3; }));
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	CHECK(channel->sent_count() == 2);
	engine.stop_workers();
}

void test_probe_port_is_delayed_when_region_enforcement_is_off()
{
	fakes::reset();
	PacketEngine engine(passive_options(5000));
	engine.start_workers();
	const auto channel = fakes::channel_with_filter("tcp");
	channel->inject(tcp_packet(1, 0, kSyn, 40000, kProbePort), 1, true);
	CHECK(wait_until([&] { return channel->consumed() == 1; }));
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	CHECK(channel->sent_count() == 0);
	engine.stop_workers();
}

void test_passive_runs_before_region_enforcement()
{
	fakes::reset();
	PacketEngineOptions options					   = passive_options(50);
	options.servers								   = {{"34.0.0.1", "eu1", "EU"}, {"35.0.0.1", "na1", "NA"}};
	options.features.region_enforcement.enabled	   = true;
	options.features.region_enforcement.probe_port = kProbePort;
	PacketEngine engine(options);
	engine.start_workers();
	engine.cycle_enforced_region(1);
	const auto passive	   = fakes::channel_with_filter("tcp");
	const auto enforcement = fakes::channel_with_filter("region_enforcement:35.0.0.1,:55002");
	CHECK(passive != nullptr && enforcement != nullptr);
	CHECK(passive->options.priority > enforcement->options.priority);
	engine.stop_workers();
}
#	endif
}  // namespace

int main(int argc, char** argv)
{
	logging::set_level(logging::level::error);
	static const test::TestCase cases[] = {
		{"disabled_passive_latency_opens_nothing", test_disabled_passive_latency_opens_nothing},
		{"starting_the_workers_opens_the_passive_channel", test_starting_the_workers_opens_the_passive_channel},
		{"custom_filter_overrides_global_filter", test_custom_filter_overrides_global_filter},
		{"delayed_packets_are_released_after_about_the_configured_delay",
		 test_delayed_packets_are_released_after_about_the_configured_delay},
		{"order_is_preserved_for_equal_delays", test_order_is_preserved_for_equal_delays},
		{"overflow_releases_packets_immediately", test_overflow_releases_packets_immediately},
		{"stopping_the_workers_flushes_and_closes_the_channel", test_stopping_the_workers_flushes_and_closes_the_channel},
		{"passive_channel_is_distinct_from_profile_channels", test_passive_channel_is_distinct_from_profile_channels},
		{"inbound_only_leaves_outbound_packets_undelayed", test_inbound_only_leaves_outbound_packets_undelayed},
		{"per_direction_overrides", test_per_direction_overrides},
		{"jitter_modes_preserve_order", test_jitter_modes_preserve_order},
		{"status_text", test_status_text},
		{"pause_flushes_and_lets_packets_through", test_pause_flushes_and_lets_packets_through},
#	ifndef NDEBUG
		{"packet_group_logs_each_packet", test_packet_group_logs_each_packet},
#	endif
		{"the_baseline_runs_as_a_shaping_stage", test_the_baseline_runs_as_a_shaping_stage},
		{"an_inbound_delay_keeps_the_baseline_in_user_space", test_an_inbound_delay_keeps_the_baseline_in_user_space},
		{"pausing_the_kernel_baseline_deactivates_the_stage", test_pausing_the_kernel_baseline_deactivates_the_stage},
		{"the_bpf_tier_does_not_fall_back_for_the_baseline", test_the_bpf_tier_does_not_fall_back_for_the_baseline},
		{"toggling_without_a_channel_is_harmless", test_toggling_without_a_channel_is_harmless},
#	ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
		{"probe_port_traffic_is_not_delayed", test_probe_port_traffic_is_not_delayed},
		{"probe_port_is_delayed_when_region_enforcement_is_off", test_probe_port_is_delayed_when_region_enforcement_is_off},
		{"passive_runs_before_region_enforcement", test_passive_runs_before_region_enforcement},
#	endif
	};
	return test::run_tests("passive_latency", cases, argc, argv);
}

#else

int main()
{
	std::puts("passive_latency: skipped, feature not compiled in");
	return 0;
}

#endif
