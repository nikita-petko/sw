#include "profile_controller.h"

#include <algorithm>

#include "log.h"
#include "platform.h"

namespace {
bool shares_activation_key(const ProfileOptions& first, const ProfileOptions& second)
{
	for (const int first_key : first.keys)
		if (std::find(second.keys.begin(), second.keys.end(), first_key) != second.keys.end())
			return true;
	return false;
}

bool is_toggle_release_mode(PacketDelayMode mode)
{
	return mode == PacketDelayMode::drop_until_toggle || mode == PacketDelayMode::hold_until_deactivation ||
		   mode == PacketDelayMode::packet_group_send;
}

const char* toggle_release_mode_name(PacketDelayMode mode)
{
	return mode == PacketDelayMode::drop_until_toggle		  ? "drop_until_toggle"
		   : mode == PacketDelayMode::hold_until_deactivation ? "hold_until_deactivation"
															  : "packet_group_send";
}
}  // namespace

ProfileController::ProfileController(PacketEngine& engine, const PacketEngineOptions& options)
: engine_(engine)
, options_(options)
, activation_key_held_(options.profiles.size(), false)
, send_key_held_(options.profiles.size(), false)
, pending_activation_(options.profiles.size(), false)
, disable_at_(options.profiles.size(), 0)
, period_deactivate_at_(options.profiles.size(), 0)
{
}

bool ProfileController::running(size_t index) const
{
	return engine_.is_running(static_cast<int>(index + 1));
}

bool ProfileController::send_key_down(size_t index) const
{
	return options_.profiles[index].send_key && platform::is_key_held(*options_.profiles[index].send_key);
}

std::vector<bool> ProfileController::find_active_profiles() const
{
	std::vector<bool> active(options_.profiles.size(), false);
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		const ProfileOptions& profile = options_.profiles[index];
		if (profile.key_mode == ProfileKeyMode::oneof)
		{
			for (const int key : profile.keys)
				active[index] = active[index] || platform::is_key_held(key);
		}
		else
		{
			active[index] = true;
			for (const int key : profile.keys)
				active[index] = active[index] && platform::is_key_held(key);
		}
	}
	return active;
}

bool ProfileController::disables(size_t source, size_t target) const
{
	const std::vector<std::string>& names = options_.profiles[source].disables;
	return std::find(names.begin(), names.end(), "*") != names.end() ||
		   std::find(names.begin(), names.end(), options_.profiles[target].name) != names.end();
}

bool ProfileController::has_active_disable_target(size_t source) const
{
	for (size_t target = 0; target < options_.profiles.size(); ++target)
		if (target != source && disables(source, target) && running(target))
			return true;
	return false;
}

// Profiles that are held with a common key are one group: the group is "running" only when all of its held members are.
bool ProfileController::all_shared_profiles_running(size_t index) const
{
	for (size_t target = 0; target < options_.profiles.size(); ++target)
	{
		if (!active_profiles_[target] || !shares_activation_key(options_.profiles[index], options_.profiles[target]))
			continue;
		if (!running(target))
			return false;
	}
	return true;
}

bool ProfileController::shared_group_has_new_activation(size_t index) const
{
	for (size_t target = 0; target < options_.profiles.size(); ++target)
	{
		if (!active_profiles_[target] || !shares_activation_key(options_.profiles[index], options_.profiles[target]))
			continue;
		if (!activation_key_held_[target])
			return true;
	}
	return false;
}

void ProfileController::setup_profile(size_t index)
{
	disable_targets(index);
	if (options_.profiles[index].respect_disable_wait && has_active_disable_target(index))
	{
		pending_activation_[index] = true;
		return;
	}
	pending_activation_[index] = false;
	engine_.setup(static_cast<int>(index + 1));
	if (running(index) && options_.profiles[index].mode == ProfileActivationMode::period)
		period_deactivate_at_[index] = platform::tick_ms() + options_.profiles[index].activation_period_ms;
}

// Deactivates the profile now, or after its disable wait (a fixed time plus a percentage of how long it has been running).
void ProfileController::schedule_teardown(size_t target, bool immediate)
{
	period_deactivate_at_[target] = 0;
	if (!running(target))
		return;
	const ProfileOptions& target_options	 = options_.profiles[target];
	const uint64_t		  enabled_for_ms	 = engine_.profile_running_time_ms(static_cast<int>(target + 1));
	const uint64_t		  percentage_wait_ms = (enabled_for_ms / 100) * target_options.disable_wait_percent +
											   (enabled_for_ms % 100) * target_options.disable_wait_percent / 100;
	const uint64_t		  wait_ms			 = target_options.disable_wait_ms + percentage_wait_ms;
	if (immediate || wait_ms == 0)
	{
		disable_at_[target] = 0;
		engine_.teardown(static_cast<int>(target + 1));
		return;
	}
	if (disable_at_[target] == 0)
	{
		disable_at_[target] = platform::tick_ms() + wait_ms;
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
}

void ProfileController::disable_targets(size_t source)
{
	for (const std::string& disabled_name : options_.profiles[source].disables)
	{
		for (size_t target = 0; target < options_.profiles.size(); ++target)
		{
			if (target == source || (disabled_name != "*" && options_.profiles[target].name != disabled_name))
				continue;
			disabled_profiles_[target] = true;
			schedule_teardown(target, !options_.profiles[source].respect_disable_wait);
			if (disabled_name != "*")
				break;
		}
	}
}

void ProfileController::end_expired_periods(uint64_t now)
{
	for (size_t index = 0; index < options_.profiles.size(); ++index)
		if (period_deactivate_at_[index] != 0 && now >= period_deactivate_at_[index])
		{
			LOG_ACTIVATE("Profile %zu reached its activation period", index + 1);
			schedule_teardown(index, false);
		}
}

void ProfileController::end_expired_disable_waits(uint64_t now)
{
	for (size_t index = 0; index < options_.profiles.size(); ++index)
		if (disable_at_[index] != 0 && now >= disable_at_[index])
			schedule_teardown(index, true);
}

// Profiles that had to wait for a disabled profile to stop are started once nothing they disable is running.
void ProfileController::activate_pending_profiles()
{
	for (size_t index = 0; index < options_.profiles.size(); ++index)
		if (pending_activation_[index] && !has_active_disable_target(index))
			setup_profile(index);
	for (size_t index = 0; index < options_.profiles.size(); ++index)
		if (options_.profiles[index].mode == ProfileActivationMode::hold && !active_profiles_[index])
			pending_activation_[index] = false;
}

// A profile switches in when its key is newly down, another profile disabled it, and none of the running profiles that
// disable it can be kept (the running ones only block it if it does not disable them back).
void ProfileController::find_switch_profiles()
{
	switch_profiles_.assign(options_.profiles.size(), false);
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		if (!disabled_profiles_[index] || !active_profiles_[index] || activation_key_held_[index])
			continue;
		bool can_swap = true;
		for (size_t source = 0; source < options_.profiles.size(); ++source)
		{
			if (running(source) && disables(source, index) && !disables(index, source))
			{
				can_swap = false;
				break;
			}
		}
		switch_profiles_[index] = can_swap;
	}
}

void ProfileController::apply_switches()
{
	if (std::find(switch_profiles_.begin(), switch_profiles_.end(), true) == switch_profiles_.end())
		return;
	for (size_t source = 0; source < options_.profiles.size(); ++source)
	{
		if (!running(source))
			continue;
		for (size_t target = 0; target < options_.profiles.size(); ++target)
			if (switch_profiles_[target] && disables(source, target))
			{
				schedule_teardown(source, !options_.profiles[target].respect_disable_wait);
				break;
			}
	}
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		if (!switch_profiles_[index])
			continue;
		LOG_DEBUG("Switching to profile %d", static_cast<int>(index + 1));
		setup_profile(index);
		activation_key_held_[index] = active_profiles_[index];
		LOG_DEBUG("Profile %d activated after disabling mutually exclusive profiles", static_cast<int>(index + 1));
	}
}

void ProfileController::update_hold_profile(size_t index)
{
	[[maybe_unused]] const int profile = static_cast<int>(index + 1);
	if (active_profiles_[index] && !running(index))
	{
		LOG_DEBUG("Setting up profile %d", profile);
		setup_profile(index);
		LOG_DEBUG("Profile %d activated (hold mode)", profile);
	}
	if (!active_profiles_[index] && running(index))
	{
		LOG_DEBUG("Disabling profile %d", profile);
		schedule_teardown(index, false);
		LOG_DEBUG("Profile %d deactivated (hold mode)", profile);
	}
}

void ProfileController::update_toggle_profile(size_t index)
{
	const int			  profile = static_cast<int>(index + 1);
	const ProfileOptions& options = options_.profiles[index];
	if (switch_profiles_[index] || !active_profiles_[index] || !shared_group_activated_[index])
		return;
	if (shared_profiles_running_[index] && running(index) && is_toggle_release_mode(options.delay_mode))
	{
		LOG_DEBUG("Toggling profile %d", profile);
		if (engine_.toggle(profile))
		{
			schedule_teardown(index, false);
			LOG_DEBUG("Profile %d released and deactivated (%s mode)", profile, toggle_release_mode_name(options.delay_mode));
		}
	}
	else if (shared_profiles_running_[index] && running(index))
	{
		if (disable_at_[index] != 0)
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

void ProfileController::update_profile(size_t index)
{
	const int  profile			= static_cast<int>(index + 1);
	const bool send_key_pressed = send_key_down(index) && !send_key_held_[index];
	if (disabled_profiles_[index])
	{
		activation_key_held_[index] = active_profiles_[index];
		send_key_held_[index]		= send_key_down(index);
		return;
	}
	if (send_key_pressed && running(index))
	{
		LOG_DEBUG("Flushing packets for profile %d on send_key", profile);
		engine_.flush_on_demand(profile);
	}
	if (options_.profiles[index].mode == ProfileActivationMode::hold)
		update_hold_profile(index);
	else
		update_toggle_profile(index);
	if (running(index))
		disable_targets(index);
	activation_key_held_[index] = active_profiles_[index];
	send_key_held_[index]		= send_key_down(index);
}

void ProfileController::update()
{
	const size_t count = options_.profiles.size();
	active_profiles_   = find_active_profiles();
	disabled_profiles_.assign(count, false);
	shared_profiles_running_.assign(count, false);
	shared_group_activated_.assign(count, false);
	for (size_t index = 0; index < count; ++index)
	{
		shared_profiles_running_[index] = all_shared_profiles_running(index);
		shared_group_activated_[index]	= shared_group_has_new_activation(index);
	}

	const uint64_t now = platform::tick_ms();
	end_expired_periods(now);
	end_expired_disable_waits(now);
	for (size_t index = 0; index < count; ++index)
		if (running(index))
			disable_targets(index);
	activate_pending_profiles();
	find_switch_profiles();
	apply_switches();
	for (size_t index = 0; index < count; ++index)
		update_profile(index);
}
