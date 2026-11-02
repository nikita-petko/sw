#include "internal.h"

#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <system_error>

#include "format.h"
#include "log.h"

LOG_DEFAULT_GROUP(logging::group::profile)

namespace {
backend::ShapingConfig shaping_config(const LinuxBpfOptions& options)
{
	backend::ShapingConfig config;
	config.tier		  = options.tier == LinuxTier::nfqueue ? backend::ShapingTier::capture
						: options.tier == LinuxTier::bpf   ? backend::ShapingTier::kernel
														   : backend::ShapingTier::automatic;
	config.interfaces = options.interfaces;
	return config;
}

const char* delay_mode_text(PacketDelayMode mode)
{
	switch (mode)
	{
		case PacketDelayMode::from_timestamp:
			return "from_timestamp";
		case PacketDelayMode::send_all_after_delay:
			return "send_all_after_delay";
		case PacketDelayMode::ratio:
			return "ratio";
		case PacketDelayMode::drop:
			return "drop";
		case PacketDelayMode::drop_and_send:
			return "drop_and_send";
		case PacketDelayMode::hold_and_send:
			return "hold_and_send";
		case PacketDelayMode::drop_until_toggle:
			return "drop_until_toggle";
		case PacketDelayMode::hold_until_deactivation:
			return "hold_until_deactivation";
		case PacketDelayMode::packet_group_send:
			return "packet_group_send";
	}
	return "unknown";
}

/// Describes how a profile would run as a kernel-shaping stage. Returns false with `reason` when its behaviour needs the
/// packets themselves in user space, so it must use a capture channel.
bool profile_shape_spec(const ProfileOptions& profile,
						[[maybe_unused]] bool pcap,
						const std::string&	  filter,
						bool				  forward,
						backend::ShapeSpec&	  spec,
						std::string&		  reason)
{
	switch (profile.delay_mode)
	{
		case PacketDelayMode::from_timestamp:
			spec.behaviour = backend::ShapeBehaviour::fixed_delay;
			break;
		case PacketDelayMode::send_all_after_delay:
			spec.behaviour = backend::ShapeBehaviour::batch_delay;
			break;
		case PacketDelayMode::drop:
			spec.behaviour = backend::ShapeBehaviour::drop;
			break;
		default:
			reason = std::string("delay mode ") + delay_mode_text(profile.delay_mode) + " decides per packet in user space";
			return false;
	}
	if (profile.capture_options.sniff.value_or(false))
	{
		reason = "sniff profiles observe packets";
		return false;
	}
	if (profile.ack_restoration)
	{
		reason = "ack_restoration rewrites packets";
		return false;
	}
	if (profile.retransmission_mode != RetransmissionMode::none)
	{
		reason = "retransmission filtering inspects packets";
		return false;
	}
	if (pcap)
	{
		reason = "PCAP capture needs the packets";
		return false;
	}
	if (spec.behaviour != backend::ShapeBehaviour::drop && profile.delay_ms <= 0)
	{
		reason = "a delay of 0 holds packets until deactivation";
		return false;
	}
	spec.filter	  = filter;
	spec.forward  = forward;
	spec.delay_ms = static_cast<uint32_t>(profile.delay_ms);
	spec.label	  = profile.name;
	return true;
}

void log_profile_enabled([[maybe_unused]] int				 profile,
						 const ProfileOptions&				 profile_options,
						 [[maybe_unused]] const std::string& capture_filter,
						 [[maybe_unused]] bool				 forward)
{
	LOG_DEBUG_GROUP(logging::group::profile, "profile #%d - %s setup: opening handle", profile, profile_options.name.c_str());
	LOG_DEBUG_GROUP(logging::group::profile,
					"profile #%d - %s setup: backend = %s, forward = %d, filter = %s",
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
	backend::configure_shaping(shaping_config(options_.features.linux_bpf));
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
			LOG_SERVER_GROUP(logging::group::server, "Pre-configured server: %s", label.c_str());
		else
		{
			if (logged_server_groups.insert(server.group).second)
				LOG_SERVER_GROUP(logging::group::server, "Pre-configured server group '%s':", server.group.c_str());
			LOG_SERVER_GROUP(logging::group::server, "  %s", label.c_str());
		}
	}
	const bool no_initial_server = !options_.initial_server || *options_.initial_server == "none";
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	state_->select_authoritative_server = no_initial_server;
#endif
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
		if (server_index_ == 0 && !no_initial_server)
			LOG_WARN_GROUP(logging::group::server, "Server '%s' does not exist; using none", options_.initial_server->c_str());
	}
	LOG_SERVER_GROUP(logging::group::server, "Initial server: %s", current_server().c_str());
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

#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
bool PacketEngine::is_authoritative_server() const
{
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	return state_->authoritative_server;
}
#endif

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
	std::string							 open_error;
	std::unique_ptr<backend::ShapeStage> shape;
	if (options_.features.linux_bpf.tier != LinuxTier::nfqueue)
	{
		backend::ShapeSpec shape_spec;
		bool			   pcap = false;
#ifdef LAGSW_FEATURE_PCAP_FILES
		pcap = pcap_files_enabled_for(options_.features.pcap_files, profile_options);
#endif
		std::string reason;
		if (profile_shape_spec(profile_options, pcap, capture_filter, forward, shape_spec, reason))
			shape = backend::open_shape_stage(shape_spec, reason);
		if (shape && !shape->activate(reason))
			shape.reset();
		if (!shape)
		{
			if (options_.features.linux_bpf.tier == LinuxTier::bpf)
			{
				LOG_ERROR("profile #%d - %s setup: kernel shaping is required (linux_bpf tier bpf) but unavailable: %s",
						  profile,
						  profile_options.name.c_str(),
						  reason.c_str());
				platform::end_timer_resolution();
				return;
			}
			LOG_DEBUG_GROUP(logging::group::profile,
							"profile #%d - %s setup: using NFQUEUE, not kernel shaping: %s",
							profile,
							profile_options.name.c_str(),
							reason.c_str());
		}
		else
			LOG_INFO("profile #%d - %s runs in the kernel (eBPF + fq), packets do not reach user space",
					 profile,
					 profile_options.name.c_str());
	}
	std::unique_ptr<backend::PacketChannel> handle;
	if (!shape)
	{
		handle = backend::open(open_options, open_error);
		if (!handle)
		{
			LOG_ERROR("profile #%d - %s setup: failed to open capture channel: %s",
					  profile,
					  profile_options.name.c_str(),
					  open_error.c_str());
			platform::end_timer_resolution();
			return;
		}
	}
	const bool				 in_kernel = shape != nullptr;
	std::shared_ptr<Session> session(new Session(profile, std::move(handle), packet_modes_[profile - 1].get()));
	session->shape = std::move(shape);
	if (!in_kernel)
		packet_modes_[profile - 1]->set_discard_sink([weak_session = std::weak_ptr<Session>(session)](const backend::PacketMeta& meta) {
			if (const std::shared_ptr<Session> locked = weak_session.lock())
				locked->handle->discard(meta);
		});
#ifdef LAGSW_FEATURE_PCAP_FILES
	if (pcap_files_enabled_for(options_.features.pcap_files, profile_options))
		start_pcap_capture(options_.features.pcap_files, profile, profile_options, session->pcap);
#endif
	state_->profile_stats[profile - 1].enabled_since = platform::tick_ms();
	state_->active_sessions[profile - 1]			 = session;
	state_->active_profiles[profile - 1]			 = true;
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	{
		std::lock_guard<std::mutex> discovery_lock(state_->discovery_mutex);
		state_->discovery_counts.clear();
	}
#endif
	packet_modes_[profile - 1]->reset();
	running_ = true;
	if (!in_kernel)
	{
		session->receive_thread = std::thread(&PacketEngine::read_packets, this, session);
		session->send_thread	= std::thread(&PacketEngine::write_packets, this, session);
	}
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
	LOG_DEBUG_GROUP(logging::group::profile, "profile #%d teardown: requested", profile);
	uint64_t				 enabled_time = 0;
	std::shared_ptr<Session> session;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
			return;
		session = state_->active_sessions[profile - 1];
		if (!session)
			return;
		LOG_DEBUG_GROUP(logging::group::profile,
						"profile #%d - %s teardown: stopping workers",
						profile,
						options_.profiles[profile - 1].name.c_str());
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
		// A kernel-shaping stage stops affecting traffic as soon as it is deactivated; packets already stamped still leave on time.
		if (session->shape)
			session->shape->deactivate();
		if (session->handle)
			session->handle->shutdown_recv();
		session->packet_changed.notify_all();
		state_->cleanup_threads.emplace_back([this, session, enabled_time, profile] {
			if (session->receive_thread.joinable())
				session->receive_thread.join();
			if (session->send_thread.joinable())
				session->send_thread.join();
#ifdef LAGSW_FEATURE_PCAP_FILES
			const bool pcap_captured = session->pcap.file != nullptr;
			if (pcap_captured)
				session->pcap.file.reset();
#endif
			if (session->handle)
				session->handle->close();
			platform::end_timer_resolution();
			LOG_DEACTIVATE("profile #%d - %s teardown: disabled after %s",
						   profile,
						   options_.profiles[profile - 1].name.c_str(),
						   logging::format_duration(enabled_time).c_str());
#ifdef LAGSW_FEATURE_PCAP_FILES
			if (pcap_captured)
				LOG_INFO("profile #%d - %s PCAP capture: %s (GUID: %s)",
						 profile,
						 options_.profiles[profile - 1].name.c_str(),
						 session->pcap.path.c_str(),
						 session->pcap.guid.c_str());
#endif
		});
	}
}

void PacketEngine::teardown()
{
	for (size_t index = 0; index < options_.profiles.size(); ++index)
		teardown(static_cast<int>(index + 1));
}
