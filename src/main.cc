#include <windows.h>

#include <conio.h>
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

const char* format_mode(ProfileActivationMode mode)
{
	return mode == ProfileActivationMode::hold ? "hold" : "toggle";
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

	LOG_INFO("Loaded profiles (%zu):", options.profiles.size());
	for (const ProfileOptions& profile : options.profiles)
	{
		const bool		  indefinite_delay = profile.delay_ms <= 0 && (profile.delay_mode == PacketDelayMode::from_timestamp ||
																	   profile.delay_mode == PacketDelayMode::send_all_after_delay ||
																	   profile.delay_mode == PacketDelayMode::drop_and_send);
		const std::string delay_description =
			indefinite_delay && profile.delay_mode == PacketDelayMode::send_all_after_delay ? "Send all until"
			: indefinite_delay && profile.delay_mode == PacketDelayMode::drop_and_send		? "Drop, then send until"
			: indefinite_delay																? "Delay each until"
			: profile.delay_mode == PacketDelayMode::send_all_after_delay					? "Send all in"
			: profile.delay_mode == PacketDelayMode::ratio
				? "Send " + std::to_string(profile.ratio) + (profile.ratio_percent ? "% per" : " packets per")
			: profile.delay_mode == PacketDelayMode::drop_and_send ? "Drop, then send in"
			: profile.delay_mode == PacketDelayMode::drop_until_toggle ? "Drop, hold, then send"
			: profile.delay_mode == PacketDelayMode::drop		   ? "Drop packets"
																   : "Delay each by";
		const std::string delay_value = indefinite_delay ? "profile is deactivated"
										: profile.delay_mode == PacketDelayMode::drop
											? "immediately"
											: logging::format_duration(static_cast<uint64_t>(profile.delay_ms));
		LOG_INFO("\"%s\" -> %s %s (press: %s, key_mode: %s, mode: %s) @ \"%s\"",
				 profile.name.c_str(),
				 delay_description.c_str(),
				 delay_value.c_str(),
				 format_keys(profile).c_str(),
				 format_key_mode(profile.key_mode),
				 format_mode(profile.mode),
				 profile.filter.value_or(options.global_filter).c_str());
	}

	::SetConsoleCtrlHandler(nullptr, TRUE);

	PacketEngine engine(options);
	LOG_INFO("Hold a configured profile key to start/stop packet capture, 'q' or backspace to quit.");
	engine.start_workers();
	std::atomic<bool> status_shutdown = false;
	std::thread		  status_thread([&] {
		while (!status_shutdown.load())
		{
			std::string status = "(STOPPED)";
			if (engine.is_running())
			{
				const size_t   pending_packets = engine.pending_packets();
				const uint64_t next_batch	   = engine.next_batch_in_ms();
				const std::string held_for	   = "; held for " + logging::format_duration(engine.running_time_ms());
				status = pending_packets == 0 ? "(RUNNING: 0 packets waiting; waiting for first packet...)"
						 : next_batch == (std::numeric_limits<uint64_t>::max)()
							 ? "(RUNNING: " + std::to_string(pending_packets) + " packets waiting; waiting for profile deactivation...)"
							 : "(RUNNING: " + std::to_string(pending_packets) + " packets waiting; " +
								   logging::format_duration(next_batch) + " left until next batch...)";
				status.insert(status.size() - 1, held_for);
			}
			std::string active_profiles;
			for (size_t index = 0; index < options.profiles.size(); ++index)
			{
				if (!engine.is_running(static_cast<int>(index + 1)))
					continue;
				if (!active_profiles.empty())
					active_profiles += ", ";
				active_profiles += options.profiles[index].name;
			}
			const std::string server_status = "server: " + engine.current_server();
			logging::set_status(status, server_status + (active_profiles.empty() ? "" : " | " + active_profiles));
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	});
	std::vector<bool> activation_key_held(options.profiles.size(), false);

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
		if (key == VK_TAB)
		{
			engine.print_state();
			continue;
		}

		const std::vector<bool> active_profiles = find_active_profiles(options);
		for (size_t index = 0; index < options.profiles.size(); ++index)
		{
			const int profile = static_cast<int>(index + 1);
			if (options.profiles[index].mode == ProfileActivationMode::hold)
			{
				if (active_profiles[index] && !engine.is_running(profile))
				{
					LOG_DEBUG("Setting up profile %d", profile);
					engine.setup(profile);
					LOG_DEBUG("Profile %d activated (hold mode)", profile);
				}
				if (!active_profiles[index] && engine.is_running(profile))
				{
					LOG_DEBUG("Disabling profile %d", profile);
					engine.teardown(profile);
					LOG_DEBUG("Profile %d deactivated (hold mode)", profile);
				}
			}
			else if (active_profiles[index] && !activation_key_held[index])
			{
				if (engine.is_running(profile) && options.profiles[index].delay_mode == PacketDelayMode::drop_until_toggle)
				{
					LOG_DEBUG("Toggling profile %d", profile);
					if (engine.toggle(profile))
					{
						engine.teardown(profile);
						LOG_DEBUG("Profile %d released and deactivated (drop_until_toggle mode)", profile);
					}
				}
				else if (engine.is_running(profile))
				{
					LOG_DEBUG("Disabling profile %d", profile);
					engine.teardown(profile);
					LOG_DEBUG("Profile %d deactivated (toggle mode)", profile);
				}
				else
				{
					LOG_DEBUG("Setting up profile %d", profile);
					engine.setup(profile);
					LOG_DEBUG("Profile %d activated (toggle mode)", profile);
				}
			}
			activation_key_held[index] = active_profiles[index];
		}
	}

	engine.teardown();
	engine.stop_workers();
	status_shutdown = true;
	status_thread.join();
	logging::clear_status();
	return 0;
}
