#include <string>

#include "format.h"
#include "log.h"
#include "options.h"
#include "packet_backend.h"
#include "packet_engine.h"
#include "platform.h"
#include "profile_controller.h"
#include "status_line.h"

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
};

KeyAction handle_command_key(PacketEngine& engine, int key)
{
	if (key == 'q' || key == 'Q' || key == platform::key::backspace)
		return KeyAction::quit;
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
	else
		return KeyAction::none;
	return KeyAction::handled;
}
}  // namespace

int main(int argc, char* argv[])
{
	platform::enable_terminal_colors();
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
	if (!parse_options(argc, argv, options))
		return 0;
#ifdef LAGSW_FEATURE_PCAP_FILES
	if (options.features.pcap_files.enabled)
		LOG_WARN("PCAP file capture is enabled for debugging. Do not use it during normal operation.");
#endif
	log_loaded_profiles(options);

	platform::ignore_interrupt();

	PacketEngine engine(options);
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	const char* region_keys_help = "left/right to cycle enforced server, ";
#else
	const char* region_keys_help = "";
#endif
	LOG_INFO("Hold a configured profile key to start/stop packet capture, pgup/pgdn to cycle servers, %s'q' or backspace to quit.",
			 region_keys_help);
	engine.start_workers();
	StatusLine		  status_line(engine, options);
	ProfileController controller(engine, options);

	while (true)
	{
		const int key = platform::read_key();
		if (key != -1)
			LOG_DEBUG("Input received: %d", key);

		const KeyAction action = handle_command_key(engine, key);
		if (action == KeyAction::quit)
			break;
		if (action == KeyAction::handled)
			continue;
		controller.update();
	}

	engine.teardown();
	engine.stop_workers();
	status_line.stop();
	logging::clear_status();
	return 0;
}
