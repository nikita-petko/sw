// Regression tests for the profiles YAML loader (src/options/). Run from the project root: `xmake test options_test`.
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "options/internal.h"
#include "support/capture.h"
#include "support/test.h"

namespace {
using test::capture_stdout;

struct LoadResult
{
	bool				ok = false;
	PacketEngineOptions options;
	std::string			log;
};

LoadResult load_file(const std::string& path)
{
	LoadResult result;
	result.log = capture_stdout([&] { result.ok = config::load_profiles(path.c_str(), result.options); });
	return result;
}

LoadResult load_text(const std::string& yaml)
{
	const std::filesystem::path path = std::filesystem::temp_directory_path() / "lagsw_options_test.yml";
	{
		std::ofstream file(path, std::ios::binary);
		file << yaml;
	}
	LoadResult result = load_file(path.string());
	std::filesystem::remove(path);
	return result;
}

const std::string kProfile = "profiles:\n  - name: \"A\"\n    key: x\n";

void test_shipped_profiles()
{
	const LoadResult div1 = load_file("profiles/div1.sw.yml");
	CHECK(div1.ok);
	const PacketEngineOptions& options = div1.options;
	CHECK(options.profiles.size() == 5);
	CHECK(options.servers.size() == 10);
	CHECK(options.servers[2].address == "34.13.202.203" && options.servers[2].name == "GR-EUC-203" && options.servers[2].group == "EU");
	CHECK(options.discovery_port == 55000);
#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
	CHECK(options.features.desync_countdown.enabled);
	CHECK(options.features.desync_countdown.display == DesyncCountdownDisplay::override_activation);
	CHECK(options.features.desync_countdown.enabled_for.size() == 2);
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	CHECK(!options.features.forwarded_address_discovery.enabled);
	CHECK(options.features.forwarded_address_discovery.inbound_if_idx == 5u);
	CHECK(options.features.forwarded_address_discovery.outbound_if_idx == 67u);
#endif

	const ProfileOptions& trickle = options.profiles[0];
	CHECK(trickle.name == "Trickle");
	CHECK(trickle.keys == std::vector<int>{'X'});
	CHECK(trickle.disables == std::vector<std::string>{"*"});
	CHECK(trickle.delay_ms == 500);
	CHECK(trickle.capture_options.forward == true);
	CHECK(trickle.capture_options.client_address_enforcement == CaptureOptions::ClientAddressEnforcement::both);

	const ProfileOptions& recv = options.profiles[1];
	CHECK(recv.keys == (std::vector<int>{'Z', 0x20}));
	CHECK(recv.key_mode == ProfileKeyMode::oneof);
	CHECK(recv.delay_mode == PacketDelayMode::ratio);
	CHECK(recv.ratio == 10 && recv.ratio_percent && recv.ratio_configured);
	CHECK(recv.capture_options.server_direction == CaptureOptions::ServerDirection::source);

	CHECK(options.profiles[3].disable_wait_percent == 15);
	CHECK(options.profiles[2].respect_disable_wait == false);
	CHECK(options.profiles[4].mode == ProfileActivationMode::period && options.profiles[4].activation_period_ms == 3000);

	const LoadResult gateway = load_file("profiles/gateway.test.sw.yml");
	CHECK(gateway.ok);
	CHECK(gateway.options.global_filter == "tcp.DstPort == 8080 or tcp.SrcPort == 8080");
	CHECK(gateway.options.discovery_port == 8080 && gateway.options.discovery_window_ms == 2000);

	CHECK(load_file("profiles/localhost.test.sw.yml").ok);
}

void test_every_setting()
{
	const LoadResult result = load_text(R"(global_filter: "tcp"
servers:
  discovery_port: 1234
  interval: 3000
  addresses: ["1.1.1.1:one", '2.2.2.2', 3.3.3.3:three]
  GROUP:
    - "4.4.4.4:four"
    - 1.1.1.1:duplicate
features:
  region_enforcement:
    enabled: true
    probe_port: 8080
  pcap_files:
    enabled: true
    output_dir: "caps"
    enabled_for: ["A", B]
  desync_countdown:
    enabled: true
    display: until_reactivated
    duration_percent: 50
    enabled_for:
      - "*"
  forwarded_address_discovery:
    enabled: true
    port: 55001
    interval: 1500
    inbound: 4
    outbound: 5
  netfilter_monitor:
    enabled: true
    interval: 500
    backlog_threshold: 42
profiles:
  - name: "A"
    keys: [x, ctrl, 0x41]
    send_key: q
    mode: hold
    disables: ["B"]
    disable_wait_ms: 100
    disable_wait_percent: 10
    respect_disable_wait: true
    retransmission_mode: both
    subsequent_packet_hold_mode: seq_ack
    ack_restoration: true
    delay_ms: 250
    filter: "udp"
    windivert_options:
      sniff: true
      forward: false
      outbound: true
      server_direction: both
      client_address_enforcement: none
  - name: B
    key: z
    mode: period
    activation_period: 1500
    delay_mode: ratio
    ratio: 25%
    ratio_selection: random
    delay_ms: 100
    amount: 4
  - name: E
    keys:
      - shift
      - alt
    delay_mode: packet_group_send
    group_count: 3
    group_order: lifo
)");
	CHECK(result.ok);
	const PacketEngineOptions& o = result.options;
	CHECK(o.global_filter == "tcp");
	CHECK(o.servers.size() == 4);  // the repeated address is ignored
	CHECK(o.servers[3].group == "GROUP" && o.servers[3].name == "four");
	CHECK(o.servers[1].name == "2.2.2.2");
	CHECK(o.discovery_port == 1234 && o.discovery_window_ms == 3000);
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	CHECK(o.features.region_enforcement.enabled && o.features.region_enforcement.probe_port == 8080);
#endif
#ifdef LAGSW_FEATURE_PCAP_FILES
	CHECK(o.features.pcap_files.enabled && o.features.pcap_files.output_dir == "caps");
	CHECK(o.features.pcap_files.enabled_for == (std::vector<std::string>{"A", "B"}));
#endif
#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
	CHECK(o.features.desync_countdown.display == DesyncCountdownDisplay::until_reactivated);
	CHECK(o.features.desync_countdown.duration_percent == 50);
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	CHECK(o.features.forwarded_address_discovery.port == 55001 && o.features.forwarded_address_discovery.window_ms == 1500);
#endif
#ifdef LAGSW_FEATURE_NETFILTER_MONITOR
	CHECK(o.features.netfilter_monitor.enabled && o.features.netfilter_monitor.interval_ms == 500 &&
		  o.features.netfilter_monitor.backlog_threshold == 42);
#endif

	const ProfileOptions& a = o.profiles[0];
	CHECK(a.keys == (std::vector<int>{'X', 0x11, 0x41}));
	CHECK(a.send_key == 'Q');
	CHECK(a.mode == ProfileActivationMode::hold);
	CHECK(a.disables == std::vector<std::string>{"B"});
	CHECK(a.disable_wait_ms == 100 && a.disable_wait_percent == 10);
	CHECK(a.retransmission_mode == RetransmissionMode::both);
	CHECK(a.subsequent_packet_hold_mode == SubsequentPacketHoldMode::seq_ack);
	CHECK(a.ack_restoration && a.delay_ms == 250 && a.filter == "udp");
	CHECK(a.capture_options.sniff == true && a.capture_options.forward == false && a.capture_options.outbound == true);
	CHECK(a.capture_options.server_direction == CaptureOptions::ServerDirection::both);
	CHECK(a.capture_options.client_address_enforcement == CaptureOptions::ClientAddressEnforcement::none);

	const ProfileOptions& b = o.profiles[1];
	CHECK(b.activation_period_ms == 1500 && b.ratio == 25 && b.ratio_percent && b.amount == 4);
	CHECK(b.ratio_selection == RatioSelection::random);

	const ProfileOptions& e = o.profiles[2];
	CHECK(e.keys == (std::vector<int>{0x10, 0x12}));
	CHECK(e.group_count == 3 && e.group_order == PacketGroupOrder::lifo);
}

/// A YAML document that must be rejected, and the message the logger should print.
struct ErrorCase
{
	const char* name;
	std::string yaml;
	const char* message;
};

void test_rejected_files()
{
	const std::vector<ErrorCase> cases = {
		{"no profiles", "servers:\n  discovery_port: 1\n", "No profiles found"},
		{"missing key", "profiles:\n  - name: A\n", "requires a name and key(s)"},
		{"line without colon", "profiles:\n  - name: A\n    nonsense\n", "Invalid YAML in"},
		{"bad key", "profiles:\n  - name: A\n    key: nonsense\n", "Invalid profile key in"},
		{"tab key", "profiles:\n  - name: A\n    key: tab\n", "Tab is reserved"},
		{"empty disabled name", kProfile + "    disables: [x,,y]\n", "Invalid disabled profile in"},
		{"unknown disabled profile", kProfile + "    disables: [Z]\n", "disables unknown profile 'Z'"},
		{"self disable", kProfile + "    disables: [A]\n", "cannot disable itself"},
		{"two send keys", kProfile + "    send_key: [a, b]\n", "must contain exactly one key"},
		{"send key is activation key", kProfile + "    send_key: x\n", "send_key cannot be an activation key"},
		{"bad mode", kProfile + "    mode: sometimes\n", "Invalid profile mode in"},
		{"bad key mode", kProfile + "    key_mode: all\n", "Invalid profile key_mode in"},
		{"bad delay mode", kProfile + "    delay_mode: wait\n", "Invalid delay_mode in"},
		{"bad boolean", kProfile + "    ack_restoration: yes\n", "Invalid ack_restoration in"},
		{"bad delay", kProfile + "    delay_ms: soon\n", "Invalid delay_ms in"},
		{"negative amount", kProfile + "    amount: -1\n", "Invalid amount in"},
		{"bad ratio", kProfile + "    ratio: 5x\n", "Invalid ratio in"},
		{"zero activation period", kProfile + "    activation_period: 0\n", "Invalid activation_period in"},
		{"period without mode", kProfile + "    activation_period: 10\n", "can only set activation_period when mode is period"},
		{"period mode without period", kProfile + "    mode: period\n", "requires a positive activation_period"},
		{"ratio without delay", kProfile + "    delay_mode: ratio\n", "requires a positive ratio and delay_ms"},
		{"hold_and_send percentage", kProfile + "    delay_mode: hold_and_send\n    ratio: 5%\n", "positive packet count ratio for hold_and_send"},
		{"drop_until_toggle in hold mode", kProfile + "    mode: hold\n    delay_mode: drop_until_toggle\n", "requires toggle mode for drop_until_toggle"},
		{"group_count without packet_group_send", kProfile + "    group_count: 2\n", "can only set group_count when delay_mode is packet_group_send"},
		{"bad capture boolean", kProfile + "    capture_options:\n      sniff: maybe\n", "Invalid boolean in"},
		{"bad server direction", kProfile + "    capture_options:\n      server_direction: up\n", "Invalid server_direction in"},
		{"empty server", "servers:\n  addresses:\n    - \"\"\n" + kProfile, "Invalid empty server in"},
		{"server without name", "servers:\n  addresses: [\"1.1.1.1:\"]\n" + kProfile, "Invalid server '1.1.1.1:' in"},
		{"addresses not a list", "servers:\n  addresses: 1.1.1.1\n" + kProfile, "Invalid servers addresses list in"},
		{"unknown servers key", "servers:\n  nonsense: 1\n" + kProfile, "Invalid servers configuration key 'nonsense' in"},
		{"zero discovery port", "servers:\n  discovery_port: 0\n" + kProfile, "Invalid discovery_port in"},
		{"unknown features key", "features:\n  nonsense: 1\n" + kProfile, "Invalid features configuration key 'nonsense' in"},
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
		{"region enforcement without port", "features:\n  region_enforcement:\n    enabled: true\n" + kProfile, "probe_port is missing or invalid"},
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
		{"same interfaces", "features:\n  forwarded_address_discovery:\n    enabled: true\n    port: 1\n    inbound: 2\n    outbound: 2\n" + kProfile,
		 "different interfaces"},
		{"interface index out of range", "features:\n  forwarded_address_discovery:\n    inbound: 4294967296\n" + kProfile, "Invalid inbound interface index in"},
#endif
#ifdef LAGSW_FEATURE_PCAP_FILES
		{"pcap without profiles", "features:\n  pcap_files:\n    enabled: true\n" + kProfile, "pcap_files is enabled but enabled_for is missing"},
		{"pcap unknown profile", "features:\n  pcap_files:\n    enabled: true\n    enabled_for: [Z]\n" + kProfile, "pcap_files enables unknown profile 'Z'"},
		{"empty pcap output dir", "features:\n  pcap_files:\n    output_dir: \"\"\n" + kProfile, "Invalid pcap_files output_dir in"},
#endif
#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
		{"bad countdown display", "features:\n  desync_countdown:\n    display: never\n" + kProfile, "Invalid desync_countdown display 'never' in"},
		{"countdown percentage", "features:\n  desync_countdown:\n    duration_percent: 101\n" + kProfile, "Invalid desync_countdown duration_percent in"},
		{"countdown unknown profile", "features:\n  desync_countdown:\n    enabled: true\n    enabled_for:\n      - Z\n" + kProfile,
		 "desync_countdown enables unknown profile 'Z'"},
#endif
	};
	for (const ErrorCase& test : cases)
	{
		const LoadResult result = load_text(test.yaml);
		if (result.ok || result.log.find(test.message) == std::string::npos)
		{
			std::fprintf(stderr, "case '%s': expected failure containing '%s', got ok=%d log=%s\n", test.name, test.message, result.ok ? 1 : 0, result.log.c_str());
			++test::failure_count();
		}
	}
}

/// A features block of a feature that is not compiled into the build is skipped with a warning, so profiles can be shared
/// between builds. Features that are compiled in are covered by the other tests.
void test_disabled_features_are_ignored()
{
	struct Section
	{
		const char* name;
		bool		compiled;
	};
	const Section sections[] = {
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
		{"region_enforcement", true},
#else
		{"region_enforcement", false},
#endif
#ifdef LAGSW_FEATURE_PCAP_FILES
		{"pcap_files", true},
#else
		{"pcap_files", false},
#endif
#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
		{"desync_countdown", true},
#else
		{"desync_countdown", false},
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
		{"forwarded_address_discovery", true},
#else
		{"forwarded_address_discovery", false},
#endif
	};
	for (const Section& section : sections)
	{
		if (section.compiled)
			continue;
		const std::string yaml = std::string("features:\n  ") + section.name +
								 ":\n    enabled: true\n    nonsense: [1, 2]\n    enabled_for:\n      - Z\n    other: 3\n" + kProfile;
		const LoadResult result = load_text(yaml);
		CHECK(result.ok);
		CHECK(result.log.find(std::string("Feature ") + section.name + " in ") != std::string::npos);
		CHECK(result.log.find("not compiled into this build") != std::string::npos);
	}
}

void test_error_reports_line()
{
	const LoadResult result = load_text("profiles:\n  - name: A\n    key: x\n    delay_ms: soon\n");
	CHECK(!result.ok);
	CHECK(result.log.find("at line 4") != std::string::npos);
	CHECK(!load_file("this/file/does/not/exist.yml").ok);
}

void test_helpers()
{
	CHECK(config::trim("  a b \t\r\n") == "a b");
	CHECK(config::unquote("'x'") == "x" && config::unquote("\"x\"") == "x" && config::unquote("'x\"") == "'x\"");
	CHECK(config::parse_key("a") == 'A' && config::parse_key("VK_SHIFT") == 0x10 && config::parse_key("0x41") == 0x41);
	CHECK(!config::parse_key("nonsense"));
	CHECK(config::parse_ulong("65535", 1, 65535) == 65535ul && !config::parse_ulong("65536", 1, 65535) && !config::parse_ulong("0", 1, 65535));
	CHECK(!config::parse_ulong("12x", 0, 100) && !config::parse_ulong("", 0, 100));
	CHECK(config::parse_long("-3", -5, 5) == -3 && !config::parse_long("6", -5, 5));
	CHECK(config::parse_ullong("5000", 1) == 5000ull && !config::parse_ullong("0", 1));
}
}  // namespace

int main(int argc, char** argv)
{
	static const test::TestCase cases[] = {
		{"helpers", test_helpers},
		{"shipped_profiles", test_shipped_profiles},
		{"every_setting", test_every_setting},
		{"rejected_files", test_rejected_files},
		{"disabled_features_are_ignored", test_disabled_features_are_ignored},
		{"error_reports_line", test_error_reports_line},
	};
	return test::run_tests("options", cases, argc, argv);
}
