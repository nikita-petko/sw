#include <optional>
#include <utility>
#include <string>

#ifdef LAGSW_FEATURE_CONFIG_TUI
#include "config_tui.h"
#endif
#include "format.h"
#include "log.h"
#include "net_monitor.h"
#include "options.h"
#include "packet_backend.h"
#include "packet_engine.h"
#include "platform.h"
#include "profile_controller.h"
#include "status_line.h"
#include "version.h"

LOG_DEFAULT_GROUP(logging::group::startup)

namespace {
void log_profile(const PacketEngineOptions& options, size_t index)
{
	const ProfileOptions& profile		   = options.profiles[index];
	const std::string	  delay_action	   = format_delay_action(profile);
	const std::string	  delay_value	   = format_delay_value(profile);
	const std::string	  filter		   = profile.filter.value_or(options.global_filter);
	LOG_DETAIL("  [%zu/%zu] %s", index + 1, options.profiles.size(), profile.name.c_str());
	LOG_DETAIL("    action: %s %s", delay_action.c_str(), delay_value.c_str());
	LOG_DETAIL("    trigger: %s | key_mode: %s | mode: %s",
			   format_keys(profile).c_str(),
			   format_key_mode(profile.key_mode),
			   format_mode(profile.mode));
	LOG_DETAIL("    disables: %s | wait: %ums + %u%% | respect_wait: %s",
			   format_disable_targets(profile).c_str(),
			   profile.disable_wait_ms,
			   profile.disable_wait_percent,
			   profile.respect_disable_wait ? "true" : "false");
	LOG_DETAIL("    retransmission: %s | subsequent_packet_hold: %s | ratio: %s%s | ratio_selection: %s",
			   format_retransmission_mode(profile.retransmission_mode),
			   format_subsequent_packet_hold_mode(profile.subsequent_packet_hold_mode),
			   profile.ratio_configured ? std::to_string(profile.ratio).c_str() : "not set",
			   profile.ratio_configured && profile.ratio_percent ? "%" : (profile.ratio_configured ? " packets" : ""),
			   format_ratio_selection(profile.ratio_selection));
	LOG_DETAIL("    capture: %s", format_capture_options(profile).c_str());
	LOG_DETAIL("    filter: %s", filter.c_str());
}

void log_loaded_profiles(const PacketEngineOptions& options)
{
	LOG_INFO("Loaded profiles (%zu):", options.profiles.size());
	for (size_t index = 0; index < options.profiles.size(); ++index)
		log_profile(options, index);
}

/// What the main loop should do after a key press has been looked at.
enum class KeyAction
{
	none,	  ///< Not a command key; poll the profile activation keys.
	handled,  ///< Handled; skip the profile activation keys this round.
	quit,
	config,	  ///< Leave for the profile loader/editor.
};

#ifdef LAGSW_FEATURE_NET_MONITOR
KeyAction handle_command_key(PacketEngine& engine, NetMonitor& net_monitor, int key, int config_key)
#else
KeyAction handle_command_key(PacketEngine& engine, int key, int config_key)
#endif
{
	if (key == 'q' || key == 'Q' || key == platform::key::backspace)
		return KeyAction::quit;
	if (config_key != platform::key::none && key != platform::key::none && normalize_key(key) == config_key)
		return KeyAction::config;
#ifdef LAGSW_FEATURE_NET_MONITOR
	if (net_monitor.is_toggle_key(key))
	{
		net_monitor.toggle();
		return KeyAction::handled;
	}
	if (net_monitor.active() && net_monitor.handle_key(key))
		return KeyAction::handled;
#endif
	if (key == platform::key::page_up)
		engine.cycle_server(-1);
	else if (key == platform::key::page_down)
		engine.cycle_server(1);
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	else if (key == platform::key::left)
		engine.cycle_enforced_region(-1);
	else if (key == platform::key::right)
		engine.cycle_enforced_region(1);
#endif
	else if (key == platform::key::tab)
		engine.print_state();
#ifdef LAGSW_FEATURE_PASSIVE_LATENCY
	else if (engine.passive_latency_pause_key() && (key >= 'a' && key <= 'z' ? key - 'a' + 'A' : key) == *engine.passive_latency_pause_key())
		engine.toggle_passive_latency_pause();
#endif
	else
		return KeyAction::none;
	return KeyAction::handled;
}

/// Why run_session() returned.
enum class SessionEnd
{
	quit,
	open_config,
};

/// Runs the engine with `options` until the user quits or asks for the profile loader/editor.
SessionEnd run_session(const PacketEngineOptions& options)
{
#ifdef LAGSW_FEATURE_PCAP_FILES
	if (options.features.pcap_files.enabled)
		LOG_WARN("PCAP file capture is enabled for debugging. Do not use it during normal operation.");
#endif
	log_loaded_profiles(options);

	PacketEngine engine(options);
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	const char* region_keys_help = "left/right to cycle enforced server, ";
#else
	const char* region_keys_help = "";
#endif
#ifdef LAGSW_FEATURE_NET_MONITOR
	const std::string net_monitor_help = options.features.net_monitor.enabled ? format_key(options.features.net_monitor.key) + " for the net monitor, " : "";
#else
	const std::string net_monitor_help;
#endif
#ifdef LAGSW_FEATURE_CONFIG_TUI
	const int		   config_key	   = normalize_key(kConfigTuiKey);
	const std::string config_tui_help = format_key(kConfigTuiKey) + " for the profile loader/editor, ";
#else
	const int		   config_key = platform::key::none;
	const std::string config_tui_help;
#endif
	LOG_INFO("Hold a configured profile key to start/stop packet capture, pgup/pgdn to cycle servers, %s%s%s'q' or backspace to quit.",
			 region_keys_help, net_monitor_help.c_str(), config_tui_help.c_str());
	engine.start_workers();
	StatusLine		  status_line(engine, options);
	ProfileController controller(engine, options);
#ifdef LAGSW_FEATURE_NET_MONITOR
	NetMonitor		  net_monitor(engine, options);
	if (options.default_view == DefaultView::net_monitor)
		net_monitor.toggle();
#endif

	SessionEnd end = SessionEnd::quit;
	while (true)
	{
		const int key = platform::read_key();
		if (key != -1)
			LOG_DEBUG_GROUP(logging::group::input, "Input received: %d", key);

		const KeyAction action = 
#ifdef LAGSW_FEATURE_NET_MONITOR
			handle_command_key(engine, net_monitor, key, config_key);
#else
			handle_command_key(engine, key, config_key);
#endif
		if (action == KeyAction::quit)
			break;
		if (action == KeyAction::config)
		{
			end = SessionEnd::open_config;
			break;
		}
		if (action == KeyAction::handled)
			continue;
		controller.update();
	}

#ifdef LAGSW_FEATURE_NET_MONITOR
	net_monitor.stop();
#endif
	engine.teardown();
	engine.stop_workers();
	status_line.stop();
	logging::clear_status();
	return end;
}

/// The file named by --config, or empty.
std::string config_argument(int argc, char* argv[])
{
	std::string path;
	for (int index = 1; index + 1 < argc; ++index)
		if (std::string(argv[index]) == "--config")
			path = argv[++index];
	return path;
}
}  // namespace

int main(int argc, char* argv[])
{
	platform::enable_terminal_colors();
	logging::set_banner(version::banner());
	// Every return path has to give the console its normal scrolling back.
	struct BannerGuard
	{
		~BannerGuard() { logging::clear_banner(); }
	} banner_guard;
	if (!platform::acquire_single_instance())
	{
		LOG_ERROR("Another instance of lagsw is already running. Only one instance is allowed at a time.");
		return 1;
	}
	if (!backend::initialize())
	{
		LOG_ERROR("Failed to initialize the %s capture backend", backend::name());
		return 1;
	}

	PacketEngineOptions options;
	std::string			active_config = config_argument(argc, argv);
	bool				config_missing = false;
	if (!parse_options(argc, argv, options, nullptr, &config_missing))
		return 0;
	// Ctrl+C must not kill the process while the terminal is in a special mode
	platform::ignore_interrupt();
#ifdef LAGSW_FEATURE_CONFIG_TUI
	if (config_missing)
	{
		const config_tui::Choice choice = config_tui::run(std::nullopt);
		if (choice.outcome != config_tui::Outcome::run)
			return 0;
		active_config = choice.path;
		if (!parse_options(argc, argv, options, &active_config))
			return 0;
	}
#endif
	std::string privilege_error;
	if (!backend::check_privileges(privilege_error))
	{
		LOG_ERROR("%s", privilege_error.c_str());
		return 1;
	}

	while (run_session(options) == SessionEnd::open_config)
	{
#ifdef LAGSW_FEATURE_CONFIG_TUI
		// The engine is stopped while the profile is chosen; the new file is loaded before the old options are dropped,
		// so a file that fails to load leaves the running configuration in place.
		const config_tui::Choice choice = config_tui::run(active_config.empty() ? std::nullopt : std::optional<std::string>(active_config));
		if (choice.outcome == config_tui::Outcome::quit)
			break;
		if (choice.outcome == config_tui::Outcome::run)
		{
			PacketEngineOptions next;
			if (parse_options(argc, argv, next, &choice.path))
			{
				options		  = std::move(next);
				active_config = choice.path;
			}
			else
				LOG_ERROR("Could not load %s; continuing with the previous profile file", choice.path.c_str());
		}
#else
		break;
#endif
	}
	return 0;
}
