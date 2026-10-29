#include "status_line.h"

#include <algorithm>
#include <chrono>
#include <limits>
#include <string>

#include "log.h"

namespace {
bool desync_countdown_enabled_for(const DesyncCountdownOptions& countdown, const ProfileOptions& profile)
{
	if (!countdown.enabled)
		return false;
	return std::find(countdown.enabled_for.begin(), countdown.enabled_for.end(), "*") != countdown.enabled_for.end() ||
		   std::find(countdown.enabled_for.begin(), countdown.enabled_for.end(), profile.name) != countdown.enabled_for.end();
}

/// "(STOPPED)" or "(RUNNING: ...)" with the number of queued packets and the time until the next batch.
std::string describe_run_state(const PacketEngine& engine)
{
	if (!engine.is_running())
		return "(STOPPED)";
	const size_t	  pending_packets = engine.pending_packets();
	const uint64_t	  next_batch	  = engine.next_batch_in_ms();
	const std::string held_for		  = "; held for " + logging::format_duration(engine.running_time_ms());
	std::string		  status =
		pending_packets == 0 ? "(RUNNING: 0 packets waiting; waiting for first packet...)"
		: next_batch == (std::numeric_limits<uint64_t>::max)()
			? "(RUNNING: " + std::to_string(pending_packets) + " packets waiting; waiting for profile deactivation...)"
			: "(RUNNING: " + std::to_string(pending_packets) + " packets waiting; " + logging::format_duration(next_batch) +
				  " left until next batch...)";
	status.insert(status.size() - 1, held_for);
	return status;
}

/// The running profiles with their packet status and, for period profiles, the time left.
std::string describe_active_profiles(const PacketEngine& engine, const PacketEngineOptions& options)
{
	const bool	override_activation = options.features.desync_countdown.display == DesyncCountdownDisplay::override_activation;
	std::string active_profiles;
	for (size_t index = 0; index < options.profiles.size(); ++index)
	{
		const ProfileOptions& profile = options.profiles[index];
		const int			  number  = static_cast<int>(index + 1);
		if (!engine.is_running(number))
			continue;
		if (override_activation && profile.delay_mode != PacketDelayMode::packet_group_send &&
			desync_countdown_enabled_for(options.features.desync_countdown, profile) && engine.profile_desync_countdown_ms(number))
			continue;
		if (!active_profiles.empty())
			active_profiles += ", ";
		active_profiles += profile.name;
		const std::string packet_status = engine.profile_packet_status(number);
		if (!packet_status.empty())
			active_profiles += " [" + packet_status + "]";
		if (profile.mode == ProfileActivationMode::period)
		{
			const uint64_t elapsed_ms	= engine.profile_running_time_ms(number);
			const uint64_t remaining_ms = elapsed_ms >= profile.activation_period_ms ? 0 : profile.activation_period_ms - elapsed_ms;
			active_profiles += " (" + logging::format_duration(remaining_ms) + " left)";
		}
	}
	return active_profiles;
}

/// The estimated desync time left for each profile that has the countdown enabled.
std::string describe_desync_countdowns(const PacketEngine& engine, const PacketEngineOptions& options)
{
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
	return desync_countdowns;
}

/// The selected server with its regions and the region-enforcement and forwarded-address-discovery state.
std::string describe_server(const PacketEngine& engine)
{
	const std::string server_region = engine.current_server_region();
	const std::string client_region = engine.client_region();
	std::string		  region;
	if (!server_region.empty() || !client_region.empty())
		region = (server_region.empty() ? "unknown" : server_region) + "/" + (client_region.empty() ? "unknown" : client_region);
	std::string server_status =
		engine.current_server() + (engine.is_authoritative_server() ? " (authoritative)" : "") + (region.empty() ? "" : " | " + region);
	if (engine.is_region_enforcement_enabled())
	{
		const std::string re_status = engine.region_enforcement_status();
		server_status += " | enforce: " + engine.current_enforced_region();
		if (!re_status.empty())
			server_status += " (" + re_status + ")";
	}
	if (engine.is_forwarded_address_discovery_enabled())
		server_status += " | fad: " + engine.forwarded_address_discovery_status();
	return server_status;
}
}  // namespace

StatusLine::StatusLine(const PacketEngine& engine, const PacketEngineOptions& options)
: engine_(engine)
, options_(options)
, thread_([this] { run(); })
{
}

StatusLine::~StatusLine()
{
	stop();
}

void StatusLine::stop()
{
	shutdown_ = true;
	if (thread_.joinable())
		thread_.join();
}

void StatusLine::run()
{
	while (!shutdown_.load())
	{
		const std::string status			= describe_run_state(engine_);
		const std::string active_profiles	= describe_active_profiles(engine_, options_);
		const std::string desync_countdowns = describe_desync_countdowns(engine_, options_);
		const std::string server_status		= describe_server(engine_);
		logging::set_status(status,
							server_status + (active_profiles.empty() ? "" : " | " + active_profiles) +
								(desync_countdowns.empty() ? "" : " | desync: " + desync_countdowns));
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}
