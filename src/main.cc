#include <windows.h>

#include <conio.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <limits>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "log.h"
#include "options.h"
#include "packet_engine.h"
#include "windivert_runtime.h"

namespace {
int get_key_without_waiting()
{
	if (!_kbhit())
		return -1;
	const int key = _getch();
	if (key != 0 && key != 0xE0)
		return key;
	const int extended_key = _getch();
	if (extended_key == 0x4B)
		return VK_LEFT;
	if (extended_key == 0x4D)
		return VK_RIGHT;
	if (extended_key == 0x49)
		return VK_PRIOR;
	if (extended_key == 0x51)
		return VK_NEXT;
	return -1;
}

bool is_key_held(int key)
{
	return (::GetAsyncKeyState(key) & 0x8000) != 0;
}

bool profiles_share_activation_key(const ProfileOptions& first, const ProfileOptions& second)
{
	for (const int first_key : first.keys)
		if (std::find(second.keys.begin(), second.keys.end(), first_key) != second.keys.end())
			return true;
	return false;
}

std::vector<bool> find_active_profiles(const PacketEngineOptions& options)
{
	std::vector<bool> active(options.profiles.size(), false);
	for (size_t index = 0; index < options.profiles.size(); ++index)
	{
		const ProfileOptions& profile = options.profiles[index];
		if (profile.key_mode == ProfileKeyMode::oneof)
		{
			for (const int key : profile.keys)
				active[index] = active[index] || is_key_held(key);
		}
		else
		{
			active[index] = true;
			for (const int key : profile.keys)
				active[index] = active[index] && is_key_held(key);
		}
	}
	return active;
}

bool desync_countdown_enabled_for(const DesyncCountdownOptions& countdown, const ProfileOptions& profile)
{
	if (!countdown.enabled)
		return false;
	return std::find(countdown.enabled_for.begin(), countdown.enabled_for.end(), "*") != countdown.enabled_for.end() ||
		   std::find(countdown.enabled_for.begin(), countdown.enabled_for.end(), profile.name) != countdown.enabled_for.end();
}

const char* format_mode(ProfileActivationMode mode)
{
	return mode == ProfileActivationMode::hold ? "hold" : mode == ProfileActivationMode::period ? "period" : "toggle";
}

const char* format_key_mode(ProfileKeyMode mode)
{
	return mode == ProfileKeyMode::oneof ? "oneof" : "combination";
}

std::string format_key(int key)
{
	if (key == VK_SPACE)
		return "space";
	if (key == VK_MENU)
		return "alt";
	if (key == VK_CONTROL)
		return "ctrl";
	if (key == VK_SHIFT)
		return "shift";
	if (key >= 0x20 && key <= 0x7E)
		return std::string(1, static_cast<char>(key));
	return std::to_string(key);
}

std::string format_keys(const ProfileOptions& profile)
{
	std::string result;
	const char* separator = profile.key_mode == ProfileKeyMode::oneof ? " or " : "+";
	for (const int key : profile.keys)
	{
		if (!result.empty())
			result += separator;
		result += format_key(key);
	}
	return result;
}

std::string format_disable_targets(const ProfileOptions& profile)
{
	if (profile.disables.empty())
		return "none";
	std::string result;
	for (size_t index = 0; index < profile.disables.size(); ++index)
	{
		if (index != 0)
			result += ", ";
		result += profile.disables[index];
	}
	return result;
}

const char* format_retransmission_mode(RetransmissionMode mode)
{
	switch (mode)
	{
		case RetransmissionMode::none:
			return "none";
		case RetransmissionMode::only_seq:
			return "only_seq";
		case RetransmissionMode::only_ack:
			return "only_ack";
		case RetransmissionMode::both:
			return "both";
	}
	return "unknown";
}

const char* format_subsequent_packet_hold_mode(SubsequentPacketHoldMode mode)
{
	switch (mode)
	{
		case SubsequentPacketHoldMode::none:
			return "none";
		case SubsequentPacketHoldMode::seq_only:
			return "seq_only";
		case SubsequentPacketHoldMode::ack_only:
			return "ack_only";
		case SubsequentPacketHoldMode::seq_ack:
			return "seq_ack";
	}
	return "unknown";
}

const char* format_ratio_selection(RatioSelection selection)
{
	switch (selection)
	{
		case RatioSelection::first:
			return "first";
		case RatioSelection::last:
			return "last";
		case RatioSelection::random:
			return "random";
	}
	return "unknown";
}

std::string format_windivert_options(const ProfileOptions& profile)
{
	std::string result;
	const auto	append = [&](const char* label, const std::string& value) {
		if (!result.empty())
			result += ", ";
		result += label;
		result += "=";
		result += value;
	};
	if (profile.windivert_options.sniff)
		append("sniff", profile.windivert_options.sniff.value() ? "true" : "false");
	if (profile.windivert_options.forward)
		append("forward", profile.windivert_options.forward.value() ? "true" : "false");
	if (profile.windivert_options.outbound)
		append("outbound", profile.windivert_options.outbound.value() ? "true" : "false");
	if (profile.windivert_options.client_address_enforcement)
	{
		static const char* client_enforcement[] = {"none", "source", "destination", "both"};
		append("client_addr", client_enforcement[static_cast<int>(profile.windivert_options.client_address_enforcement.value())]);
	}
	if (profile.windivert_options.server_direction)
	{
		static const char* server_direction[] = {"source", "destination", "both"};
		append("server_dir", server_direction[static_cast<int>(profile.windivert_options.server_direction.value())]);
	}
	return result.empty() ? "default" : result;
}

void enable_virtual_terminal()
{
	HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD  mode	  = 0;
	if (output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode))
		SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}
}  // namespace

int main(int argc, char* argv[])
{
	enable_virtual_terminal();
	if (!initialize_windivert())
	{
		LOG_ERROR("Failed to initialize embedded WinDivert");
		return 1;
	}

	PacketEngineOptions options;
	if (!parse_options(argc, argv, options))
		return 0;
	if (options.features.pcap_files.enabled)
		LOG_WARN("PCAP file capture is enabled for debugging. Do not use it during normal operation.");

	LOG_INFO("Loaded profiles (%zu):", options.profiles.size());
	for (size_t index = 0; index < options.profiles.size(); ++index)
	{
		const ProfileOptions& profile		   = options.profiles[index];
		const bool			  indefinite_delay = profile.delay_ms <= 0 && (profile.delay_mode == PacketDelayMode::from_timestamp ||
																		   profile.delay_mode == PacketDelayMode::send_all_after_delay ||
																		   profile.delay_mode == PacketDelayMode::drop_and_send);
		const std::string	  delay_description =
			indefinite_delay && profile.delay_mode == PacketDelayMode::send_all_after_delay ? "Send all after"
			: indefinite_delay && profile.delay_mode == PacketDelayMode::drop_and_send		? "Drop, then send after"
			: indefinite_delay																? "Delay each by"
			: profile.delay_mode == PacketDelayMode::send_all_after_delay					? "after"
			: profile.delay_mode == PacketDelayMode::ratio
				? "Send " + std::to_string(profile.ratio) + (profile.ratio_percent ? "% per" : " packets per")
			: profile.delay_mode == PacketDelayMode::drop_and_send	   ? "Drop, then send after"
			: profile.delay_mode == PacketDelayMode::hold_and_send	   ? "Hold, then send"
			: profile.delay_mode == PacketDelayMode::drop_until_toggle ? "Drop, hold, then send after"
			: profile.delay_mode == PacketDelayMode::hold_until_deactivation ? "Hold, then send on deactivation"
			: profile.delay_mode == PacketDelayMode::drop			   ? "Drop packets"
																	   : "Delay each by";
		const std::string delay_value = indefinite_delay ? "profile is deactivated"
										: profile.delay_mode == PacketDelayMode::drop
											? "immediately"
											: logging::format_duration(static_cast<uint64_t>(profile.delay_ms));
		const std::string filter	  = profile.filter.value_or(options.global_filter);
		LOG_DETAIL("  [%zu/%zu] %s", index + 1, options.profiles.size(), profile.name.c_str());
		LOG_DETAIL("    action: %s %s", delay_description.c_str(), delay_value.c_str());
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
		LOG_DETAIL("    windivert: %s", format_windivert_options(profile).c_str());
		LOG_DETAIL("    filter: %s", filter.c_str());
	}

	::SetConsoleCtrlHandler(nullptr, TRUE);

	PacketEngine engine(options);
	LOG_INFO(
		"Hold a configured profile key to start/stop packet capture, pgup/pgdn to cycle servers, left/right to cycle enforced server, 'q' "
		"or backspace to quit.");
	engine.start_workers();
	std::atomic<bool>	  status_shutdown = false;
	std::thread			  status_thread([&] {
		while (!status_shutdown.load())
		{
			std::string status = "(STOPPED)";
			if (engine.is_running())
			{
				const size_t	  pending_packets = engine.pending_packets();
				const uint64_t	  next_batch	  = engine.next_batch_in_ms();
				const std::string held_for		  = "; held for " + logging::format_duration(engine.running_time_ms());
				status = pending_packets == 0 ? "(RUNNING: 0 packets waiting; waiting for first packet...)"
						 : next_batch == (std::numeric_limits<uint64_t>::max)()
							 ? "(RUNNING: " + std::to_string(pending_packets) + " packets waiting; waiting for profile deactivation...)"
							 : "(RUNNING: " + std::to_string(pending_packets) + " packets waiting; " +
								   logging::format_duration(next_batch) + " left until next batch...)";
				status.insert(status.size() - 1, held_for);
			}
			const bool override_activation =
				options.features.desync_countdown.display == DesyncCountdownDisplay::override_activation;
			std::string active_profiles;
			for (size_t index = 0; index < options.profiles.size(); ++index)
			{
				if (!engine.is_running(static_cast<int>(index + 1)))
					continue;
				if (override_activation && desync_countdown_enabled_for(options.features.desync_countdown, options.profiles[index]) &&
					engine.profile_desync_countdown_ms(static_cast<int>(index + 1)))
					continue;
				if (!active_profiles.empty())
					active_profiles += ", ";
				active_profiles += options.profiles[index].name;
				if (options.profiles[index].mode == ProfileActivationMode::period)
				{
					const uint64_t elapsed_ms = engine.profile_running_time_ms(static_cast<int>(index + 1));
					const uint64_t remaining_ms = elapsed_ms >= options.profiles[index].activation_period_ms
												  ? 0
												  : options.profiles[index].activation_period_ms - elapsed_ms;
					active_profiles += " (" + logging::format_duration(remaining_ms) + " left)";
				}
			}
			std::string desync_countdowns;
			for (size_t index = 0; index < options.profiles.size(); ++index)
			{
				if (!desync_countdown_enabled_for(options.features.desync_countdown, options.profiles[index]))
					continue;
				const auto remaining_ms = engine.profile_desync_countdown_ms(static_cast<int>(index + 1));
				if (!remaining_ms)
					continue;
				if (!desync_countdowns.empty())
					desync_countdowns += ", ";
				desync_countdowns += options.profiles[index].name + " ~" + logging::format_duration(*remaining_ms) + " left";
			}
			const std::string server_region = engine.current_server_region();
			const std::string client_region = engine.client_region();
			std::string		  region;
			if (!server_region.empty() || !client_region.empty())
				region = (server_region.empty() ? "unknown" : server_region) + "/" + (client_region.empty() ? "unknown" : client_region);
			std::string server_status = engine.current_server() + (engine.is_authoritative_server() ? " (authoritative)" : "") +
										(region.empty() ? "" : " | " + region);
			if (engine.is_region_enforcement_enabled())
			{
				const std::string re_status = engine.region_enforcement_status();
				server_status += " | enforce: " + engine.current_enforced_region();
				if (!re_status.empty())
					server_status += " (" + re_status + ")";
			}
			if (engine.is_forwarded_address_discovery_enabled())
				server_status += " | fad: " + engine.forwarded_address_discovery_status();
			logging::set_status(status,
							server_status + (active_profiles.empty() ? "" : " | " + active_profiles) +
							(desync_countdowns.empty() ? "" : " | desync: " + desync_countdowns));
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	});
	std::vector<bool>	  activation_key_held(options.profiles.size(), false);
	std::vector<uint64_t> disable_at(options.profiles.size(), 0);
	std::vector<uint64_t> period_deactivate_at(options.profiles.size(), 0);
	std::vector<bool>	  pending_activation(options.profiles.size(), false);
	std::vector<bool>	  send_key_held(options.profiles.size(), false);



	while (true)
	{
		const int key = get_key_without_waiting();
		if (key != -1)
			LOG_DEBUG("Input received: %d", key);

		if (key == 'q' || key == 'Q' || key == VK_BACK)
			break;
		if (key == VK_PRIOR)
		{
			engine.cycle_server(-1);
			continue;
		}
		if (key == VK_NEXT)
		{
			engine.cycle_server(1);
			continue;
		}
		if (key == VK_LEFT)
		{
			engine.cycle_enforced_region(-1);
			continue;
		}
		if (key == VK_RIGHT)
		{
			engine.cycle_enforced_region(1);
			continue;
		}
		if (key == VK_TAB)
		{
			engine.print_state();
			continue;
		}

		const std::vector<bool> active_profiles = find_active_profiles(options);
		std::vector<bool>		disabled_profiles(options.profiles.size(), false);
		auto					all_shared_profiles_running = [&](size_t index) {
			for (size_t target = 0; target < options.profiles.size(); ++target)
			{
				if (!active_profiles[target] || !profiles_share_activation_key(options.profiles[index], options.profiles[target]))
					continue;
				if (!engine.is_running(static_cast<int>(target + 1)))
					return false;
			}
			return true;
		};
		auto shared_group_has_new_activation = [&](size_t index) {
			for (size_t target = 0; target < options.profiles.size(); ++target)
			{
				if (!active_profiles[target] || !profiles_share_activation_key(options.profiles[index], options.profiles[target]))
					continue;
				if (!activation_key_held[target])
					return true;
			}
			return false;
		};
		std::vector<bool> shared_profiles_running(options.profiles.size(), false);
		std::vector<bool> shared_group_activated(options.profiles.size(), false);
		for (size_t index = 0; index < options.profiles.size(); ++index)
		{
			shared_profiles_running[index] = all_shared_profiles_running(index);
			shared_group_activated[index]  = shared_group_has_new_activation(index);
		}
		auto profile_disables = [&](size_t source, size_t target) {
			return std::find(options.profiles[source].disables.begin(), options.profiles[source].disables.end(), "*") !=
					   options.profiles[source].disables.end() ||
				   std::find(options.profiles[source].disables.begin(),
							 options.profiles[source].disables.end(),
							 options.profiles[target].name) != options.profiles[source].disables.end();
		};
		auto schedule_teardown = [&](size_t target, bool immediate) {
			period_deactivate_at[target] = 0;
			if (!engine.is_running(static_cast<int>(target + 1)))
				return;
			const ProfileOptions& target_options	 = options.profiles[target];
			const uint64_t		  enabled_for_ms	 = engine.profile_running_time_ms(static_cast<int>(target + 1));
			const uint64_t		  percentage_wait_ms = (enabled_for_ms / 100) * target_options.disable_wait_percent +
													   (enabled_for_ms % 100) * target_options.disable_wait_percent / 100;
			const uint64_t		  wait_ms			 = target_options.disable_wait_ms + percentage_wait_ms;
			if (immediate || wait_ms == 0)
			{
				disable_at[target] = 0;
				engine.teardown(static_cast<int>(target + 1));
				return;
			}
			if (disable_at[target] == 0)
			{
				disable_at[target] = GetTickCount64() + wait_ms;
				if (percentage_wait_ms != 0)
					LOG_DEACTIVATE("Profile %zu will deactivate in %s (%s extra from %u%% of %s)",
							 target + 1,
							 logging::format_duration(wait_ms).c_str(),
							 logging::format_duration(percentage_wait_ms).c_str(),
							 target_options.disable_wait_percent,
							 logging::format_duration(enabled_for_ms).c_str());
				else
					LOG_DEACTIVATE("Profile %zu will deactivate in %s", target + 1, logging::format_duration(wait_ms).c_str());
			}
		};
		auto disable_targets = [&](size_t source) {
			for (const std::string& disabled_name : options.profiles[source].disables)
			{
				for (size_t target = 0; target < options.profiles.size(); ++target)
				{
					if (target == source || (disabled_name != "*" && options.profiles[target].name != disabled_name))
						continue;
					disabled_profiles[target] = true;
					schedule_teardown(target, !options.profiles[source].respect_disable_wait);
					if (disabled_name != "*")
						break;
				}
			}
		};
		auto has_active_disable_target = [&](size_t source) {
			for (size_t target = 0; target < options.profiles.size(); ++target)
				if (target != source && profile_disables(source, target) && engine.is_running(static_cast<int>(target + 1)))
					return true;
			return false;
		};
		auto setup_profile = [&](size_t index) {
			disable_targets(index);
			if (options.profiles[index].respect_disable_wait && has_active_disable_target(index))
			{
				pending_activation[index] = true;
				return;
			}
			pending_activation[index] = false;
			engine.setup(static_cast<int>(index + 1));
			if (engine.is_running(static_cast<int>(index + 1)) && options.profiles[index].mode == ProfileActivationMode::period)
				period_deactivate_at[index] = GetTickCount64() + options.profiles[index].activation_period_ms;
		};
		const uint64_t now = GetTickCount64();
		for (size_t index = 0; index < options.profiles.size(); ++index)
			if (period_deactivate_at[index] != 0 && now >= period_deactivate_at[index])
			{
				LOG_ACTIVATE("Profile %zu reached its activation period", index + 1);
				schedule_teardown(index, false);
			}
		for (size_t index = 0; index < options.profiles.size(); ++index)
			if (disable_at[index] != 0 && now >= disable_at[index])
				schedule_teardown(index, true);
		for (size_t index = 0; index < options.profiles.size(); ++index)
			if (engine.is_running(static_cast<int>(index + 1)))
				disable_targets(index);
		for (size_t index = 0; index < options.profiles.size(); ++index)
			if (pending_activation[index] && !has_active_disable_target(index))
				setup_profile(index);
		for (size_t index = 0; index < options.profiles.size(); ++index)
			if (options.profiles[index].mode == ProfileActivationMode::hold && !active_profiles[index])
				pending_activation[index] = false;
		std::vector<bool> switch_profiles(options.profiles.size(), false);
		for (size_t index = 0; index < options.profiles.size(); ++index)
		{
			if (!disabled_profiles[index] || !active_profiles[index] || activation_key_held[index])
				continue;
			bool can_swap = true;
			for (size_t source = 0; source < options.profiles.size(); ++source)
			{
				if (engine.is_running(static_cast<int>(source + 1)) && profile_disables(source, index) && !profile_disables(index, source))
				{
					can_swap = false;
					break;
				}
			}
			switch_profiles[index] = can_swap;
		}
		if (std::find(switch_profiles.begin(), switch_profiles.end(), true) != switch_profiles.end())
		{
			for (size_t source = 0; source < options.profiles.size(); ++source)
			{
				if (!engine.is_running(static_cast<int>(source + 1)))
					continue;
				for (size_t target = 0; target < options.profiles.size(); ++target)
					if (switch_profiles[target] && profile_disables(source, target))
					{
						schedule_teardown(source, !options.profiles[target].respect_disable_wait);
						break;
					}
			}
			for (size_t index = 0; index < options.profiles.size(); ++index)
			{
				if (!switch_profiles[index])
					continue;
				LOG_DEBUG("Switching to profile %d", static_cast<int>(index + 1));
				setup_profile(index);
				activation_key_held[index] = active_profiles[index];
				LOG_DEBUG("Profile %d activated after disabling mutually exclusive profiles", static_cast<int>(index + 1));
			}
		}
		for (size_t index = 0; index < options.profiles.size(); ++index)
		{
			const int profile = static_cast<int>(index + 1);
			const bool send_key_pressed = options.profiles[index].send_key && is_key_held(*options.profiles[index].send_key) && !send_key_held[index];
			if (disabled_profiles[index])
			{
				activation_key_held[index] = active_profiles[index];
				send_key_held[index] = options.profiles[index].send_key && is_key_held(*options.profiles[index].send_key);
				continue;
			}
			if (send_key_pressed && engine.is_running(profile))
			{
				LOG_DEBUG("Flushing packets for profile %d on send_key", profile);
				engine.flush_on_demand(profile);
			}
			if (options.profiles[index].mode == ProfileActivationMode::hold)
			{
				if (active_profiles[index] && !engine.is_running(profile))
				{
					LOG_DEBUG("Setting up profile %d", profile);
					setup_profile(index);
					LOG_DEBUG("Profile %d activated (hold mode)", profile);
				}
				if (!active_profiles[index] && engine.is_running(profile))
				{
					LOG_DEBUG("Disabling profile %d", profile);
					schedule_teardown(index, false);
					LOG_DEBUG("Profile %d deactivated (hold mode)", profile);
				}
			}
			else if (!switch_profiles[index] && active_profiles[index] && shared_group_activated[index])
			{
				if (shared_profiles_running[index] && engine.is_running(profile) &&
					(options.profiles[index].delay_mode == PacketDelayMode::drop_until_toggle ||
					 options.profiles[index].delay_mode == PacketDelayMode::hold_until_deactivation))
				{
					LOG_DEBUG("Toggling profile %d", profile);
					if (engine.toggle(profile))
					{
						schedule_teardown(index, false);
						LOG_DEBUG("Profile %d released and deactivated (%s mode)",
								  profile,
								  options.profiles[index].delay_mode == PacketDelayMode::drop_until_toggle ? "drop_until_toggle"
																						 : "hold_until_deactivation");
					}
				}
				else if (shared_profiles_running[index] && engine.is_running(profile))
				{
					if (disable_at[index] != 0)
					{
						LOG_DEBUG("Restarting profile %d during disable wait", profile);
						schedule_teardown(index, true);
						setup_profile(index);
						LOG_DEBUG("Profile %d restarted (toggle mode)", profile);
					}
					else
					{
						LOG_DEBUG("Disabling profile %d", profile);
						schedule_teardown(index, false);
						LOG_DEBUG("Profile %d deactivated (toggle mode)", profile);
					}
				}
				else
				{
					LOG_DEBUG("Setting up profile %d", profile);
					setup_profile(index);
					LOG_DEBUG("Profile %d activated (toggle mode)", profile);
				}
			}
			if (engine.is_running(profile))
				disable_targets(index);
			activation_key_held[index] = active_profiles[index];
			send_key_held[index] = options.profiles[index].send_key && is_key_held(*options.profiles[index].send_key);
		}
	}

	engine.teardown();
	engine.stop_workers();
	status_shutdown = true;
	status_thread.join();
	logging::clear_status();
	return 0;
}
