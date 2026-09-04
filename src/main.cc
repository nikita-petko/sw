#include <windows.h>

#include <conio.h>
#include <atomic>
#include <chrono>
#include <limits>
#include <string>
#include <thread>
#include <utility>

#include "log.h"
#include "options.h"
#include "packet_engine.h"
#include "windivert_runtime.h"

namespace {
int get_key_without_waiting()
{
	return _kbhit() ? _getch() : -1;
}

bool is_key_held(int key)
{
	return (::GetAsyncKeyState(key) & 0x8000) != 0;
}

int find_active_profile(const PacketEngineOptions& options)
{
	for (size_t index = 0; index < options.profiles.size(); ++index)
	{
		bool active = true;
		for (const int key : options.profiles[index].keys)
			active = active && is_key_held(key);
		if (active)
			return static_cast<int>(index);
	}
	return -1;
}

const char* format_mode(ProfileActivationMode mode)
{
	return mode == ProfileActivationMode::hold ? "hold" : "toggle";
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
	for (const int key : profile.keys)
	{
		if (!result.empty())
			result += "+";
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
		const std::string delay_description =
			profile.delay_mode == PacketDelayMode::send_all_after_delay ? "Send all in"
			: profile.delay_mode == PacketDelayMode::ratio
				? "Send " + std::to_string(profile.ratio) + (profile.ratio_percent ? "% per" : " packets per")
				: "Delay each by";
		LOG_INFO("\"%s\" -> %s %s (press: %s, mode: %s) @ \"%s\"",
				 profile.name.c_str(),
				 delay_description.c_str(),
				 logging::format_duration(static_cast<uint64_t>(profile.delay_ms)).c_str(),
				 format_keys(profile).c_str(),
				 format_mode(profile.mode),
				 profile.filter.value_or(options.global_filter).c_str());
	}

	::SetConsoleCtrlHandler(nullptr, TRUE);

	PacketEngine engine(options);
	LOG_INFO("Hold a configured profile key to start/stop packet capture, 'q' or backspace to quit.");
	engine.start_workers();
	std::atomic<bool> activation_key_held = false;
	std::atomic<bool> status_shutdown	  = false;
	std::thread		  status_thread([&] {
		while (!status_shutdown.load())
		{
			std::string status = "(STOPPED)";
			if (engine.is_running())
			{
				const size_t   pending_packets = engine.pending_packets();
				const uint64_t next_batch	   = engine.next_batch_in_ms();
				status = pending_packets == 0 ? "(RUNNING: 0 packets waiting; waiting for first packet...)"
						 : next_batch == (std::numeric_limits<uint64_t>::max)()
							 ? "(RUNNING: " + std::to_string(pending_packets) + " packets waiting; waiting for profile deactivation...)"
							 : "(RUNNING: " + std::to_string(pending_packets) + " packets waiting; " +
								   logging::format_duration(next_batch) + " left until next batch...)";
			}
			logging::set_status(status);
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	});
	int				  hold_profile = -1;

	while (true)
	{
		const int key = get_key_without_waiting();
		if (key != -1)
			LOG_DEBUG("Input received: %d", key);

		if (key == 'q' || key == 'Q' || key == VK_BACK)
			break;
		if (key == VK_TAB)
		{
			engine.print_state();
			continue;
		}

		const int profile = find_active_profile(options);
		if (profile != -1)
		{
			if (options.profiles[profile].mode == ProfileActivationMode::hold)
			{
				hold_profile = profile;
				if (!engine.is_running())
				{
					LOG_DEBUG("Setting up profile %d", profile + 1);
					engine.setup(profile + 1);
					LOG_DEBUG("Profile %d activated (hold mode)", profile + 1);
				}
			}
			else if (!activation_key_held)
			{
				if (engine.is_running())
				{
					LOG_DEBUG("Disabling profile %d", profile + 1);
					engine.teardown();
					LOG_DEBUG("Profile %d deactivated (toggle mode)", profile + 1);
				}
				else
				{
					LOG_DEBUG("Setting up profile %d", profile + 1);
					engine.setup(profile + 1);
					LOG_DEBUG("Profile %d activated (toggle mode)", profile + 1);
				}
			}
			activation_key_held = true;
		}

		if (hold_profile != -1 && profile != hold_profile)
		{
			LOG_DEBUG("Disabling profile %d", hold_profile + 1);
			engine.teardown();
			LOG_DEBUG("Profile %d deactivated (hold mode)", hold_profile + 1);
			hold_profile = -1;
		}
		if (profile == -1)
			activation_key_held = false;
	}

	engine.teardown();
	engine.stop_workers();
	status_shutdown = true;
	status_thread.join();
	logging::clear_status();
	return 0;
}
