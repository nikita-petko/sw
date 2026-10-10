#include "packet_engine_internal.h"

#include <objbase.h>
#include <mmsystem.h>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <system_error>

#include "log.h"

PacketEngine::PacketEngine(PacketEngineOptions options) : options_(std::move(options)), state_(new State(options_.profiles.size()))
{
	std::srand(static_cast<unsigned int>(std::time(nullptr)));
	load_region_cache(state_->region_cache);
	packet_modes_.reserve(options_.profiles.size());
	for (const ProfileOptions& profile : options_.profiles)
		packet_modes_.push_back(create_packet_mode(profile));
	state_->active_profiles.resize(options_.profiles.size());
	state_->active_sessions.resize(options_.profiles.size());
	std::unordered_set<std::string> logged_server_groups;
	for (const ServerOptions& server : options_.servers)
	{
		const std::string label = server.name == server.address ? server.address : server.name + " [" + server.address + "]";
		if (server.group.empty())
			LOG_INFO("Pre-configured server: %s", label.c_str());
		else
		{
			if (logged_server_groups.insert(server.group).second)
				LOG_INFO("Pre-configured server group '%s':", server.group.c_str());
			LOG_INFO("  %s", label.c_str());
		}
	}
	state_->select_authoritative_server = !options_.initial_server || *options_.initial_server == "none";
	if (options_.initial_server)
	{
		for (size_t index = 0; index < options_.servers.size(); ++index)
		{
			const ServerOptions& server = options_.servers[index];
			if (*options_.initial_server == server.address || *options_.initial_server == server.name)
			{
				server_index_ = index + 1;
				break;
			}
		}
		if (server_index_ == 0 && !state_->select_authoritative_server)
			LOG_WARN("Server '%s' does not exist; using none", options_.initial_server->c_str());
	}
	LOG_INFO("Initial server: %s", current_server().c_str());
}

PacketEngine::~PacketEngine()
{
	teardown();
	stop_workers();
}

bool PacketEngine::is_running() const
{
	return running_.load();
}

bool PacketEngine::is_running(int profile) const
{
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
		return false;
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	return state_->active_profiles[profile - 1];
}

bool PacketEngine::is_authoritative_server() const
{
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	return state_->authoritative_server;
}

bool PacketEngine::is_region_enforcement_enabled() const
{
	return options_.features.region_enforcement.enabled;
}

bool PacketEngine::is_forwarded_address_discovery_enabled() const
{
	return options_.features.forwarded_address_discovery.enabled;
}

std::string PacketEngine::forwarded_address_discovery_status() const
{
	if (!options_.features.forwarded_address_discovery.enabled)
		return {};

	std::lock_guard<std::mutex> lock(state_->fad_mutex);
	const std::string			 source		 = state_->fad_client_source_address.empty() ? "unknown" : state_->fad_client_source_address;
	const std::string			 destination = state_->fad_client_destination_address.empty() ? "unknown" : state_->fad_client_destination_address;
	return "src: " + source + ", dst: " + destination;
}

std::optional<std::string> PacketEngine::effective_client_source_address() const
{
	if (options_.features.forwarded_address_discovery.enabled)
	{
		std::lock_guard<std::mutex> lock(state_->fad_mutex);
		if (!state_->fad_client_source_address.empty())
			return state_->fad_client_source_address;
	}
	return options_.client_source_address;
}

std::optional<std::string> PacketEngine::effective_client_destination_address() const
{
	if (options_.features.forwarded_address_discovery.enabled)
	{
		std::lock_guard<std::mutex> lock(state_->fad_mutex);
		if (!state_->fad_client_destination_address.empty())
			return state_->fad_client_destination_address;
	}
	return options_.client_destination_address;
}

std::string PacketEngine::region_enforcement_status() const
{
	if (!options_.features.region_enforcement.enabled)
		return {};

	std::lock_guard<std::mutex> lock(state_->probe_mutex);
	if (!state_->probe_received)
		return "Waiting for probes...";

	const uint64_t now = GetTickCount64();
	if (now >= state_->next_check_time)
		return "~0s";

	const uint64_t remaining_ms = state_->next_check_time - now;
	return "~" + logging::format_duration(remaining_ms);
}

uint64_t PacketEngine::running_time_ms() const
{
	const uint64_t				now = GetTickCount64();
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	uint64_t					earliest_enabled   = now;
	bool						has_active_profile = false;
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		if (state_->active_profiles[index])
		{
			has_active_profile = true;
			earliest_enabled   = (std::min)(earliest_enabled, state_->profile_stats[index].enabled_since);
		}
	}
	return has_active_profile ? now - earliest_enabled : 0;
}

uint64_t PacketEngine::profile_running_time_ms(int profile) const
{
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
		return 0;
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	const size_t				index = static_cast<size_t>(profile - 1);
	return state_->active_profiles[index] ? GetTickCount64() - state_->profile_stats[index].enabled_since : 0;
}

std::optional<uint64_t> PacketEngine::profile_desync_countdown_ms(int profile) const
{
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
		return std::nullopt;
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	const size_t				index = static_cast<size_t>(profile - 1);
	const State::ProfileStats& stats = state_->profile_stats[index];
	if (state_->active_profiles[index] || stats.enabled_count == 0 || stats.last_disabled_at == 0)
		return std::nullopt;
	const uint64_t duration_percent = options_.features.desync_countdown.duration_percent;
	const uint64_t estimate_ms = (stats.last_enabled_time / 100) * duration_percent +
								  (stats.last_enabled_time % 100) * duration_percent / 100;
	const uint64_t elapsed_ms = GetTickCount64() - stats.last_disabled_at;
	if (elapsed_ms >= estimate_ms)
		return std::nullopt;
	return estimate_ms - elapsed_ms;
}

size_t PacketEngine::pending_packets() const
{
	size_t						pending = 0;
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	for (const auto& session : state_->active_sessions)
		if (session)
		{
			std::lock_guard<std::mutex> session_lock(session->packet_mutex);
			pending += session->delayed_packets.size();
		}
	return pending;
}

uint64_t PacketEngine::next_batch_in_ms() const
{
	uint64_t					next_release	   = (std::numeric_limits<uint64_t>::max)();
	bool						has_queued_packets = false;
	const uint64_t				now				   = GetTickCount64();
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	for (const auto& session : state_->active_sessions)
		if (session)
		{
			std::lock_guard<std::mutex> session_lock(session->packet_mutex);
			if (!session->delayed_packets.empty())
			{
				has_queued_packets = true;
				next_release	   = (std::min)(next_release, session->delayed_packets.top()->release_at);
			}
		}
	if (!has_queued_packets)
		return 0;
	if (next_release == (std::numeric_limits<uint64_t>::max)())
		return (std::numeric_limits<uint64_t>::max)();
	return next_release > now ? next_release - now : 0;
}

std::string PacketEngine::server_filter(const ProfileOptions& profile) const
{
	const std::string& filter		   = profile.filter.value_or(options_.global_filter);
	const size_t	   server_index	   = server_index_.load();
	std::string		   combined_filter = filter;
	const auto		   enforcement =
		profile.windivert_options.client_address_enforcement.value_or(WinDivertOptions::ClientAddressEnforcement::both);
	std::string client_filter;
	const std::optional<std::string> client_source		= effective_client_source_address();
	const std::optional<std::string> client_destination = effective_client_destination_address();
	if (enforcement == WinDivertOptions::ClientAddressEnforcement::source ||
		enforcement == WinDivertOptions::ClientAddressEnforcement::both)
		if (client_source)
			client_filter = "ip.SrcAddr == " + *client_source;
	if (enforcement == WinDivertOptions::ClientAddressEnforcement::destination ||
		enforcement == WinDivertOptions::ClientAddressEnforcement::both)
		if (client_destination)
		{
			if (!client_filter.empty())
				client_filter += " or ";
			client_filter += "ip.DstAddr == " + *client_destination;
		}
	if (!client_filter.empty())
		combined_filter = "(" + combined_filter + ") and (" + client_filter + ")";

	if (server_index == 0 || !profile.windivert_options.server_direction)
		return combined_filter;
	const std::string& server_address = options_.servers[server_index - 1].address;

	const char* address_field = "ip.Addr";
	switch (*profile.windivert_options.server_direction)
	{
		case WinDivertOptions::ServerDirection::source:
			address_field = "ip.SrcAddr";
			break;
		case WinDivertOptions::ServerDirection::destination:
			address_field = "ip.DstAddr";
			break;
		case WinDivertOptions::ServerDirection::both:
			break;
	}
	const std::string& server_group = options_.servers[server_index - 1].group;
	std::string		   address_filter;
	for (const ServerOptions& server : options_.servers)
	{
		if (server_group.empty() ? server.address == server_address : server.group == server_group)
		{
			if (!address_filter.empty())
				address_filter += " or ";
			address_filter += address_field + std::string(" == ") + server.address;
		}
	}
	return "(" + combined_filter + ") and (" + address_filter + ")";
}

std::string PacketEngine::current_server() const
{
	std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
	const size_t				server_index = server_index_.load();
	if (server_index != 0)
	{
		const ServerOptions& server = options_.servers[server_index - 1];
		const std::string	 label	= server.name == server.address ? server.address : server.name + " [" + server.address + "]";
		return server.group.empty() ? label : server.group + ": " + label;
	}
	return "none";
}

std::vector<std::string> PacketEngine::configured_regions() const
{
	std::vector<std::string> regions;
	for (const ServerOptions& server : options_.servers)
	{
		if (!server.group.empty())
		{
			if (std::find(regions.begin(), regions.end(), server.group) == regions.end())
				regions.push_back(server.group);
		}
	}
	if (regions.empty())
	{
		for (const ServerOptions& server : options_.servers)
		{
			const std::string& name = server.name.empty() ? server.address : server.name;
			if (!name.empty() && std::find(regions.begin(), regions.end(), name) == regions.end())
				regions.push_back(name);
		}
	}
	return regions;
}

std::string PacketEngine::current_enforced_region() const
{
	std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
	const auto					regions		 = configured_regions();
	const size_t				region_index = enforced_region_index_.load();
	if (region_index != 0 && region_index <= regions.size())
	{
		return regions[region_index - 1];
	}
	return "none";
}

std::string PacketEngine::current_server_region() const
{
	std::string address;
	{
		std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
		const size_t				server_index = server_index_.load();
		if (server_index == 0)
			return "";
		address = options_.servers[server_index - 1].address;
	}
	std::lock_guard<std::mutex> region_lock(state_->region_mutex);
	const auto					region = state_->server_regions.find(address);
	return region == state_->server_regions.end() ? "" : region->second;
}

std::string PacketEngine::client_region() const
{
	std::lock_guard<std::mutex> region_lock(state_->region_mutex);
	return state_->client_region;
}

void PacketEngine::cycle_server(int direction)
{
	if (options_.servers.empty() || direction == 0)
		return;
	const size_t option_count = options_.servers.size() + 1;
	size_t		 current	  = server_index_.load();
	if (direction > 0)
		current = (current + 1) % option_count;
	else
		current = current == 0 ? option_count - 1 : current - 1;
	server_index_						= current;
	state_->authoritative_server		= false;
	state_->select_authoritative_server = false;
	LOG_INFO("Server changed to: %s", current_server().c_str());

	std::vector<int> active_profiles;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		for (size_t index = 0; index < state_->active_profiles.size(); ++index)
			if (state_->active_profiles[index])
				active_profiles.push_back(static_cast<int>(index + 1));
	}
	for (const int profile : active_profiles)
		teardown(profile);
	for (const int profile : active_profiles)
		setup(profile);
}

void PacketEngine::cycle_enforced_region(int direction)
{
	const auto regions = configured_regions();
	if (regions.empty() || direction == 0)
		return;
	const size_t option_count = regions.size() + 1;
	size_t		 current	  = enforced_region_index_.load();
	if (direction > 0)
		current = (current + 1) % option_count;
	else
		current = current == 0 ? option_count - 1 : current - 1;
	enforced_region_index_ = current;
	LOG_INFO("Enforced region changed to: %s", current_enforced_region().c_str());

	stop_region_enforcement();
	start_region_enforcement();
}
void PacketEngine::setup(int profile)
{
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
	{
		LOG_ERROR("Profile %d is not configured", profile);
		return;
	}
	if (state_->active_sessions[profile - 1])
		return;
	timeBeginPeriod(1);
	const ProfileOptions& profile_options = options_.profiles[profile - 1];
	const bool			  sniff			  = profile_options.windivert_options.sniff.value_or(false);
	const bool			  outbound		  = profile_options.windivert_options.outbound.value_or(false);
	const bool			  forward		  = profile_options.windivert_options.forward.value_or(false);
	ProfileOptions		  capture_profile = profile_options;
	if (profile_options.ack_restoration)
	{
		const std::string& packet_filter = profile_options.filter.value_or(options_.global_filter);
		capture_profile.filter			 = "(" + packet_filter + ") or (tcp.Ack and not tcp.Psh)";
	}
	const std::string	  filter		 = server_filter(capture_profile);
	UINT				  flags			 = sniff ? WINDIVERT_FLAG_SNIFF : 0;
	const std::string	  capture_filter = outbound ? "outbound and (" + filter + ")" : filter;
	const WINDIVERT_LAYER layer			 = forward ? WINDIVERT_LAYER_NETWORK_FORWARD : WINDIVERT_LAYER_NETWORK;
	HANDLE				  handle		 = WinDivertOpen(capture_filter.c_str(), layer, 0, flags);
	if (handle == INVALID_HANDLE_VALUE)
	{
		const DWORD error = GetLastError();
		LOG_ERROR("profile #%d - %s setup: failed to open WinDivert handle %lu: %s",
				  profile,
				  profile_options.name.c_str(),
				  error,
				  format_win32_error(error).c_str());
		timeEndPeriod(1);
		return;
	}
	std::shared_ptr<Session> session(new Session(profile, handle, packet_modes_[profile - 1].get()));
	if (pcap_files_enabled_for(options_.features.pcap_files, profile_options))
	{
		GUID guid = {};
		if (FAILED(CoCreateGuid(&guid)))
			LOG_ERROR("profile #%d - %s PCAP capture: failed to generate a GUID", profile, profile_options.name.c_str());
		else
		{
			session->pcap_guid = format_guid(guid);
			std::error_code error;
			std::filesystem::create_directories(options_.features.pcap_files.output_dir, error);
			if (error)
				LOG_ERROR("profile #%d - %s PCAP capture: failed to create directory %s: %s",
						  profile,
						  profile_options.name.c_str(),
						  options_.features.pcap_files.output_dir.c_str(),
						  error.message().c_str());
			else
			{
				session->pcap_path =
					(std::filesystem::path(options_.features.pcap_files.output_dir) / (session->pcap_guid + ".pcap")).string();
				session->pcap_file = std::make_unique<std::ofstream>(session->pcap_path, std::ios::binary | std::ios::trunc);
				if (!*session->pcap_file)
				{
					LOG_ERROR("profile #%d - %s PCAP capture: failed to open %s",
							  profile,
							  profile_options.name.c_str(),
							  session->pcap_path.c_str());
					session->pcap_file.reset();
				}
				else
				{
					std::ofstream& pcap_file = *session->pcap_file;
					write_pcap_u32(pcap_file, 0xa1b2c3d4);
					write_pcap_u16(pcap_file, 2);
					write_pcap_u16(pcap_file, 4);
					write_pcap_u32(pcap_file, 0);
					write_pcap_u32(pcap_file, 0);
					write_pcap_u32(pcap_file, 0xFFFF);
					write_pcap_u32(pcap_file, 101);
					if (!pcap_file)
					{
						LOG_ERROR("profile #%d - %s PCAP capture: failed to write header to %s",
								  profile,
								  profile_options.name.c_str(),
								  session->pcap_path.c_str());
						session->pcap_file.reset();
					}
				}
			}
		}
	}
	state_->profile_stats[profile - 1].enabled_since = GetTickCount64();
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 1024);
	state_->active_sessions[profile - 1] = session;
	state_->active_profiles[profile - 1] = true;
	{
		std::lock_guard<std::mutex> discovery_lock(state_->discovery_mutex);
		state_->discovery_counts.clear();
	}
	packet_modes_[profile - 1]->reset();
	running_				= true;
	session->receive_thread = std::thread(&PacketEngine::read_packets, this, session);
	session->send_thread	= std::thread(&PacketEngine::write_packets, this, session);
	LOG_DEBUG("profile #%d - %s setup: opening handle", profile, profile_options.name.c_str());
	LOG_DEBUG("profile #%d - %s setup: WinDivert layer = %s, filter = %s",
			  profile,
			  profile_options.name.c_str(),
			  forward ? "NETWORK_FORWARD" : "NETWORK",
			  capture_filter.c_str());
	LOG_INFO("Lag switch enabled, profile = %s (%s, mode = %s). %s",
			 profile_options.name.c_str(),
			 format_keys(profile_options).c_str(),
			 profile_options.mode == ProfileActivationMode::hold ? "hold"
			 : profile_options.mode == ProfileActivationMode::period ? "period"
																								 : "toggle",
			 profile_options.mode == ProfileActivationMode::hold ? "Release key(s) to turn off" : "Press key(s) again to turn off");
}

bool PacketEngine::toggle(int profile)
{
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
		return false;
	const std::shared_ptr<Session>& session = state_->active_sessions[profile - 1];
	if (!session)
		return false;
	std::lock_guard<std::mutex> packet_lock(session->packet_mutex);
	const bool					release = session->mode->toggle(session->delayed_packets);
	session->packet_changed.notify_all();
	return release;
}

void PacketEngine::flush_on_demand(int profile)
{
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
		return;
	const std::shared_ptr<Session>& session = state_->active_sessions[profile - 1];
	if (!session)
		return;
	std::lock_guard<std::mutex> packet_lock(session->packet_mutex);
	session->mode->flush_on_demand(session->delayed_packets);
	session->packet_changed.notify_all();
}

void PacketEngine::teardown(int profile)
{
	LOG_DEBUG("profile #%d teardown: requested", profile);
	uint64_t				 enabled_time = 0;
	std::shared_ptr<Session> session;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
			return;
		session = state_->active_sessions[profile - 1];
		if (!session)
			return;
		LOG_DEBUG("profile #%d - %s teardown: stopping workers", profile, options_.profiles[profile - 1].name.c_str());
		State::ProfileStats& stats = state_->profile_stats[profile - 1];
		enabled_time			   = GetTickCount64() - stats.enabled_since;
		stats.last_enabled_time	   = enabled_time;
		stats.last_disabled_at	   = GetTickCount64();
		stats.enabled_time_total += enabled_time;
		if (enabled_time < stats.enabled_time_min)
			stats.enabled_time_min = enabled_time;
		if (enabled_time > stats.enabled_time_max)
			stats.enabled_time_max = enabled_time;
		++stats.enabled_count;
		state_->active_sessions[profile - 1].reset();
		state_->active_profiles[profile - 1] = false;
		running_		  = std::any_of(state_->active_profiles.begin(), state_->active_profiles.end(), [](bool active) { return active; });
		session->stopping = true;
		WinDivertShutdown(session->handle, WINDIVERT_SHUTDOWN_RECV);
		session->packet_changed.notify_all();
		state_->cleanup_threads.emplace_back([this, session, enabled_time, profile] {
			session->receive_thread.join();
			session->send_thread.join();
			const bool pcap_captured = session->pcap_file != nullptr;
			if (pcap_captured)
				session->pcap_file.reset();
			WinDivertClose(session->handle);
			timeEndPeriod(1);
			LOG_INFO("profile #%d - %s teardown: disabled after %s",
					 profile,
					 options_.profiles[profile - 1].name.c_str(),
					 logging::format_duration(enabled_time).c_str());
			if (pcap_captured)
				LOG_INFO("profile #%d - %s PCAP capture: %s (GUID: %s)",
						 profile,
						 options_.profiles[profile - 1].name.c_str(),
						 session->pcap_path.c_str(),
						 session->pcap_guid.c_str());
		});
	}
}

void PacketEngine::teardown()
{
	for (size_t index = 0; index < options_.profiles.size(); ++index)
		teardown(static_cast<int>(index + 1));
}
void PacketEngine::start_workers()
{
	if (options_.resolve_region)
		resolve_client_region();
	if (options_.discovery_port)
	{
		const uint16_t	  port	 = *options_.discovery_port;
		const std::string filter = "tcp.DstPort == " + std::to_string(port) + " or tcp.SrcPort == " + std::to_string(port) +
								   " or udp.DstPort == " + std::to_string(port) + " or udp.SrcPort == " + std::to_string(port);
		state_->discovery_handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);
		if (state_->discovery_handle == INVALID_HANDLE_VALUE)
		{
			const DWORD error = GetLastError();
			LOG_ERROR("Server discovery setup: failed to open WinDivert handle %lu: %s", error, format_win32_error(error).c_str());
		}
		else
		{
			WinDivertSetParam(state_->discovery_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
			WinDivertSetParam(state_->discovery_handle, WINDIVERT_PARAM_QUEUE_TIME, 1024);
			LOG_INFO("Server discovery enabled on port %u with a %s window",
					 port,
					 logging::format_duration(options_.discovery_window_ms).c_str());
			state_->discovery_thread = std::thread(&PacketEngine::discover_packets, this);
		}
	}

	if (options_.features.region_enforcement.enabled && options_.features.region_enforcement.probe_port != 0)
	{
		const uint16_t	  port = options_.features.region_enforcement.probe_port;
		const std::string filter =
			"tcp.Syn and (tcp.DstPort == " + std::to_string(port) + " or tcp.SrcPort == " + std::to_string(port) + ")";
		state_->probe_handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);
		if (state_->probe_handle == INVALID_HANDLE_VALUE)
		{
			const DWORD error = GetLastError();
			LOG_ERROR("Probe detection setup: failed to open WinDivert handle %lu: %s", error, format_win32_error(error).c_str());
		}
		else
		{
			WinDivertSetParam(state_->probe_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
			WinDivertSetParam(state_->probe_handle, WINDIVERT_PARAM_QUEUE_TIME, 1024);
			LOG_INFO("Probe detection enabled on port %u", port);
			state_->probe_thread = std::thread(&PacketEngine::probe_packets, this);
		}

		start_region_enforcement();
	}

	if (options_.features.forwarded_address_discovery.enabled)
	{
		const uint32_t	   inbound_if_idx  = *options_.features.forwarded_address_discovery.inbound_if_idx;
		const uint32_t	   outbound_if_idx = *options_.features.forwarded_address_discovery.outbound_if_idx;
		const uint16_t	   port			   = options_.features.forwarded_address_discovery.port;
		const std::string  port_filter	   = "tcp.DstPort == " + std::to_string(port) + " or tcp.SrcPort == " + std::to_string(port) +
										 " or udp.DstPort == " + std::to_string(port) + " or udp.SrcPort == " + std::to_string(port);
		const std::string filter = "outbound and (ifIdx == " + std::to_string(inbound_if_idx) + " or ifIdx == " +
								   std::to_string(outbound_if_idx) + ") and (" + port_filter + ")";
		LOG_DEBUG("Forwarded address discovery setup: opening filter '%s'", filter.c_str());
		// a dedicated priority avoids losing packets to other priority-0 handles (server discovery, profiles) with overlapping filters
		state_->fad_handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 1000, WINDIVERT_FLAG_SNIFF);
		if (state_->fad_handle == INVALID_HANDLE_VALUE)
		{
			const DWORD error = GetLastError();
			LOG_ERROR("Forwarded address discovery setup: failed to open WinDivert handle %lu: %s",
					  error,
					  format_win32_error(error).c_str());
		}
		else
		{
			WinDivertSetParam(state_->fad_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
			WinDivertSetParam(state_->fad_handle, WINDIVERT_PARAM_QUEUE_TIME, 1024);
			LOG_INFO("Forwarded address discovery enabled (inbound ifIdx %u, outbound ifIdx %u)", inbound_if_idx, outbound_if_idx);
			state_->fad_thread = std::thread(&PacketEngine::forwarded_address_discovery_recv, this);
		}
	}
}

void PacketEngine::stop_workers()
{
	shutdown_ = true;
	if (state_->discovery_handle != INVALID_HANDLE_VALUE)
		WinDivertShutdown(state_->discovery_handle, WINDIVERT_SHUTDOWN_RECV);
	if (state_->probe_handle != INVALID_HANDLE_VALUE)
		WinDivertShutdown(state_->probe_handle, WINDIVERT_SHUTDOWN_RECV);
	if (state_->fad_handle != INVALID_HANDLE_VALUE)
		WinDivertShutdown(state_->fad_handle, WINDIVERT_SHUTDOWN_RECV);
	stop_region_enforcement();
	teardown();
	for (std::thread& cleanup_thread : state_->cleanup_threads)
		if (cleanup_thread.joinable())
			cleanup_thread.join();
	if (state_->discovery_thread.joinable())
		state_->discovery_thread.join();
	if (state_->probe_thread.joinable())
		state_->probe_thread.join();
	if (state_->fad_thread.joinable())
		state_->fad_thread.join();
	for (std::thread& region_thread : state_->region_threads)
		if (region_thread.joinable())
			region_thread.join();
	state_->region_threads.clear();
	if (state_->discovery_handle != INVALID_HANDLE_VALUE)
	{
		WinDivertClose(state_->discovery_handle);
		state_->discovery_handle = INVALID_HANDLE_VALUE;
	}
	if (state_->probe_handle != INVALID_HANDLE_VALUE)
	{
		WinDivertClose(state_->probe_handle);
		state_->probe_handle = INVALID_HANDLE_VALUE;
	}
	if (state_->fad_handle != INVALID_HANDLE_VALUE)
	{
		WinDivertClose(state_->fad_handle);
		state_->fad_handle = INVALID_HANDLE_VALUE;
	}
}
