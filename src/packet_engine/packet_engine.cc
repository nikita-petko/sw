#include "internal.h"

#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <system_error>

#include "format.h"
#include "log.h"

namespace {
void log_profile_enabled(int profile, const ProfileOptions& profile_options, const std::string& capture_filter, bool forward)
{
	LOG_DEBUG("profile #%d - %s setup: opening handle", profile, profile_options.name.c_str());
	LOG_DEBUG("profile #%d - %s setup: backend = %s, forward = %d, filter = %s",
			  profile,
			  profile_options.name.c_str(),
			  backend::name(),
			  forward ? 1 : 0,
			  capture_filter.c_str());
	LOG_ACTIVATE("Lag switch enabled, profile = %s (%s, mode = %s). %s",
				 profile_options.name.c_str(),
				 format_keys(profile_options).c_str(),
				 format_mode(profile_options.mode),
				 profile_options.mode == ProfileActivationMode::hold ? "Release key(s) to turn off" : "Press key(s) again to turn off");
}
}  // namespace

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
			LOG_SERVER("Pre-configured server: %s", label.c_str());
		else
		{
			if (logged_server_groups.insert(server.group).second)
				LOG_SERVER("Pre-configured server group '%s':", server.group.c_str());
			LOG_SERVER("  %s", label.c_str());
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
	LOG_SERVER("Initial server: %s", current_server().c_str());
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
	platform::begin_timer_resolution();
	const ProfileOptions& profile_options = options_.profiles[profile - 1];
	const bool			  sniff			  = profile_options.capture_options.sniff.value_or(false);
	const bool			  forward		  = profile_options.capture_options.forward.value_or(false);
	const std::string	  capture_filter  = backend::filters::profile(server_filter(profile_options));
	backend::OpenOptions  open_options;
	open_options.filter	 = capture_filter;
	open_options.forward = forward;
	open_options.sniff	 = sniff;
	std::string open_error;
	std::unique_ptr<backend::PacketChannel> handle = backend::open(open_options, open_error);
	if (!handle)
	{
		LOG_ERROR("profile #%d - %s setup: failed to open capture channel: %s",
				  profile,
				  profile_options.name.c_str(),
				  open_error.c_str());
		platform::end_timer_resolution();
		return;
	}
	std::shared_ptr<Session> session(new Session(profile, std::move(handle), packet_modes_[profile - 1].get()));
	packet_modes_[profile - 1]->set_discard_sink([weak_session = std::weak_ptr<Session>(session)](const backend::PacketMeta& meta) {
		if (const std::shared_ptr<Session> locked = weak_session.lock())
			locked->handle->discard(meta);
	});
	if (pcap_files_enabled_for(options_.features.pcap_files, profile_options))
		start_pcap_capture(options_.features.pcap_files, profile, profile_options, session->pcap);
	state_->profile_stats[profile - 1].enabled_since = platform::tick_ms();
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
	log_profile_enabled(profile, profile_options, capture_filter, forward);
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
		enabled_time			   = platform::tick_ms() - stats.enabled_since;
		stats.last_enabled_time	   = enabled_time;
		stats.last_disabled_at	   = platform::tick_ms();
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
		session->handle->shutdown_recv();
		session->packet_changed.notify_all();
		state_->cleanup_threads.emplace_back([this, session, enabled_time, profile] {
			session->receive_thread.join();
			session->send_thread.join();
			const bool pcap_captured = session->pcap.file != nullptr;
			if (pcap_captured)
				session->pcap.file.reset();
			session->handle->close();
			platform::end_timer_resolution();
			LOG_DEACTIVATE("profile #%d - %s teardown: disabled after %s",
					 profile,
					 options_.profiles[profile - 1].name.c_str(),
					 logging::format_duration(enabled_time).c_str());
			if (pcap_captured)
				LOG_INFO("profile #%d - %s PCAP capture: %s (GUID: %s)",
						 profile,
						 options_.profiles[profile - 1].name.c_str(),
						 session->pcap.path.c_str(),
						 session->pcap.guid.c_str());
		});
	}
}

void PacketEngine::teardown()
{
	for (size_t index = 0; index < options_.profiles.size(); ++index)
		teardown(static_cast<int>(index + 1));
}
