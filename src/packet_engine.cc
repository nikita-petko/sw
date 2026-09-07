#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif
#ifndef WINVER
#	define WINVER 0x0A00
#endif
#ifndef _WIN32_WINNT
#	define _WIN32_WINNT 0x0A00
#endif

#include "packet_engine.h"

#include <windows.h>

#include <mmsystem.h>
#include <algorithm>
#include "modules/packet_mode.h"
#include <chrono>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
#include "windivert_runtime.h"

#include "log.h"

namespace {
std::string format_win32_error(DWORD error)
{
	char*		message = nullptr;
	const DWORD length	= FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
										 nullptr,
										 error,
										 0,
										 reinterpret_cast<char*>(&message),
										 0,
										 nullptr);
	if (length == 0)
		return "unknown error";

	std::string result(message, length);
	LocalFree(message);
	while (!result.empty() && (result.back() == '\r' || result.back() == '\n'))
		result.pop_back();
	return result;
}

const char* key_name(int key)
{
	if (key == 0x20)
		return "space";
	if (key == 0x12)
		return "alt";
	if (key == 0x11)
		return "ctrl";
	if (key == 0x10)
		return "shift";
	return nullptr;
}

std::string format_keys(const ProfileOptions& profile)
{
	std::string result;
	const char* separator = profile.key_mode == ProfileKeyMode::oneof ? " or " : "+";
	for (const int key : profile.keys)
	{
		if (!result.empty())
			result += separator;
		if (const char* name = key_name(key))
			result += name;
		else if (key >= 0x20 && key <= 0x7E)
			result += static_cast<char>(key);
		else
			result += std::to_string(key);
	}
	return result;
}

std::string format_state_divider(size_t width, const std::string& label = {})
{
	const size_t inner_width = width - 2;
	if (label.empty())
		return "|" + std::string(inner_width, '-') + "|";

	const std::string text		 = " " + label + " ";
	const size_t	  left_width = (inner_width - text.size()) / 2;
	return "|" + std::string(left_width, '-') + text + std::string(inner_width - left_width - text.size(), '-') + "|";
}

void log_state_line(size_t width, const std::string& text)
{
	LOG_INFO("| %-*s |", static_cast<int>(width - 4), text.c_str());
}
}  // namespace

struct PacketEngine::Session
{
	explicit Session(int profile_number, HANDLE divert_handle, PacketMode* packet_mode)
		: profile(profile_number), handle(divert_handle), mode(packet_mode) {}

	int																				 profile;
	HANDLE																			 handle;
	std::atomic<bool>																 stopping = false;
	std::mutex																		 packet_mutex;
	std::condition_variable															 packet_changed;
	uint64_t																		 next_receive_order = 0;
	PacketQueue																	 delayed_packets;
	PacketMode*												 mode;
	std::thread																		 receive_thread;
	std::thread																		 send_thread;
};

struct PacketEngine::State
{
	struct ProfileStats
	{
		uint64_t			  enabled_since			= 0;
		uint64_t			  enabled_time_total	= 0;
		uint64_t			  enabled_time_min		= (std::numeric_limits<uint64_t>::max)();
		uint64_t			  enabled_time_max		= 0;
		uint64_t			  last_enabled_time		= 0;
		uint64_t			  enabled_count			= 0;
		std::atomic<uint64_t> packets_caught		= 0;
		std::atomic<uint64_t> delayed_packets_sent	= 0;
		std::atomic<uint64_t> teardown_packets_sent = 0;
	};

	explicit State(size_t profile_count) : profile_stats(profile_count) {}

	std::mutex				  lifecycle_mutex;
	std::condition_variable	  lifecycle_changed;
	std::vector<bool> active_profiles;
	std::vector<ProfileStats> profile_stats;
	std::vector<std::shared_ptr<Session>> active_sessions;
	std::vector<std::thread>  cleanup_threads;
};

PacketEngine::PacketEngine(PacketEngineOptions options) : options_(std::move(options)), state_(new State(options_.profiles.size()))
{
	packet_modes_.reserve(options_.profiles.size());
	for (const ProfileOptions& profile : options_.profiles)
		packet_modes_.push_back(create_packet_mode(profile));
	state_->active_profiles.resize(options_.profiles.size());
	state_->active_sessions.resize(options_.profiles.size());
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
		if (server_index_ == 0)
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

uint64_t PacketEngine::running_time_ms() const
{
	const uint64_t now = GetTickCount64();
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	uint64_t earliest_enabled = now;
	bool has_active_profile = false;
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		if (state_->active_profiles[index])
		{
			has_active_profile = true;
			earliest_enabled = (std::min)(earliest_enabled, state_->profile_stats[index].enabled_since);
		}
	}
	return has_active_profile ? now - earliest_enabled : 0;
}

size_t PacketEngine::pending_packets() const
{
	size_t pending = 0;
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
	uint64_t next_release = (std::numeric_limits<uint64_t>::max)();
	bool has_queued_packets = false;
	const uint64_t now = GetTickCount64();
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	for (const auto& session : state_->active_sessions)
		if (session)
		{
			std::lock_guard<std::mutex> session_lock(session->packet_mutex);
			if (!session->delayed_packets.empty())
			{
				has_queued_packets = true;
				next_release = (std::min)(next_release, session->delayed_packets.top()->release_at);
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
	const std::string& filter = profile.filter.value_or(options_.global_filter);
	const size_t server_index = server_index_.load();
	if (server_index == 0 || !profile.windivert_options.server_direction)
		return filter;

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
	return "(" + filter + ") and " + address_field + " == " + options_.servers[server_index - 1].address;
}

std::string PacketEngine::current_server() const
{
	const size_t server_index = server_index_.load();
	return server_index == 0 ? "none" : options_.servers[server_index - 1].name;
}

void PacketEngine::cycle_server(int direction)
{
	if (options_.servers.empty() || direction == 0)
		return;
	const size_t option_count = options_.servers.size() + 1;
	size_t current = server_index_.load();
	if (direction > 0)
		current = (current + 1) % option_count;
	else
		current = current == 0 ? option_count - 1 : current - 1;
	server_index_ = current;
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

void PacketEngine::print_state() const
{
	std::vector<bool> active_profiles;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		active_profiles = state_->active_profiles;
	}

	const size_t queued_packets = pending_packets();
	const uint64_t next_release_in = next_batch_in_ms();

	size_t state_width = 53;
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		const std::string label = "profile #" + std::to_string(index + 1) + " - " + options_.profiles[index].name;
		if (label.size() + 4 > state_width)
			state_width = label.size() + 4;
	}
	const std::string max_value			 = std::to_string((std::numeric_limits<uint64_t>::max)());
	const size_t	  enabled_time_width = std::string("enabled time:    ").size() + max_value.size() + std::string("ms current, ").size() +
										   max_value.size() + std::string("ms min, ").size() + max_value.size() +
										   std::string("ms max, ").size() + max_value.size() + std::string("ms avg").size();
	if (enabled_time_width + 4 > state_width)
		state_width = enabled_time_width + 4;
	LOG_INFO("+%s+", std::string(state_width - 2, '-').c_str());
	log_state_line(state_width, std::string("status:          ") + (running_ ? "RUNNING" : "STOPPED"));
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		const size_t			   profile_number		= index + 1;
		const ProfileOptions&	   profile_options		= options_.profiles[index];
		const State::ProfileStats& stats				= state_->profile_stats[index];
		uint64_t				   enabled_time_current = 0;
		uint64_t				   last_enabled_time	= 0;
		uint64_t				   enabled_time_min		= 0;
		uint64_t				   enabled_time_total	= 0;
		uint64_t				   enabled_time_max		= 0;
		uint64_t				   enabled_count		= 0;
		{
			std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
			if (active_profiles[index])
				enabled_time_current = GetTickCount64() - stats.enabled_since;
			enabled_time_total = stats.enabled_time_total;
			enabled_time_min   = stats.enabled_count == 0 ? 0 : stats.enabled_time_min;
			enabled_time_max   = stats.enabled_time_max;
			last_enabled_time  = stats.last_enabled_time;
			enabled_count	   = stats.enabled_count;
		}
		const uint64_t enabled_time_average = enabled_count == 0 ? 0 : enabled_time_total / enabled_count;
		std::string	   profile_label		= profile_options.name;
		if (active_profiles[index])
			profile_label += " (ACTIVE)";
		else if (enabled_count != 0)
			profile_label += " (held " + logging::format_duration(last_enabled_time) + ")";
		LOG_INFO("%s", format_state_divider(state_width, profile_label).c_str());
		log_state_line(state_width, "profile:         #" + std::to_string(profile_number) + " - " + profile_options.name);
		log_state_line(state_width,
					   "enabled time:    " + logging::format_duration(enabled_time_current) + " current, " +
						   logging::format_duration(enabled_time_min) + " min, " + logging::format_duration(enabled_time_max) + " max, " +
						   logging::format_duration(enabled_time_average) + " avg");
		log_state_line(state_width,
					   "enabled total:   " + logging::format_duration(enabled_time_total) + " across " + std::to_string(enabled_count) +
						   " activations");
		log_state_line(state_width, "packets caught:  " + std::to_string(stats.packets_caught.load()));
		log_state_line(state_width, "sent after delay: " + std::to_string(stats.delayed_packets_sent.load()));
		log_state_line(state_width, "sent at teardown: " + std::to_string(stats.teardown_packets_sent.load()));
		LOG_INFO("%s", format_state_divider(state_width).c_str());
	}
	log_state_line(state_width, "queued packets:  " + std::to_string(queued_packets));
	if (queued_packets != 0)
	{
		if (next_release_in == (std::numeric_limits<uint64_t>::max)())
			log_state_line(state_width, "next release:    on profile deactivation");
		else
			log_state_line(state_width, "next release:    in " + logging::format_duration(next_release_in));
	}
	LOG_INFO("+%s+", std::string(state_width - 2, '-').c_str());
}

void PacketEngine::read_packets(const std::shared_ptr<Session>& session)
{
	const int			  profile		  = session->profile;
	const ProfileOptions& profile_options = options_.profiles[profile - 1];
	const std::string	  profile_label	  = "profile #" + std::to_string(profile) + " - " + profile_options.name;
	while (!session->stopping)
	{
		BYTE			  packet_data[0xFFFF];
		WINDIVERT_ADDRESS address;
		UINT			  received_length = 0;
		if (!WinDivertRecv(session->handle, packet_data, sizeof(packet_data), &received_length, &address))
		{
			const DWORD error = GetLastError();
			if (!session->stopping && error != ERROR_INVALID_HANDLE && error != ERROR_OPERATION_ABORTED)
				LOG_ERROR("%s recv: WinDivertRecv error %lu: %s", profile_label.c_str(), error, format_win32_error(error).c_str());
			continue;
		}
		state_->profile_stats[profile - 1].packets_caught.fetch_add(1);
		const bool sniff = profile_options.windivert_options.sniff.value_or(false);
		if (!sniff)
		{
			std::lock_guard<std::mutex> lock(session->packet_mutex);
			if (session->stopping)
				break;
			session->mode->capture(packet_data,
				received_length,
				address,
				session->profile,
				GetTickCount64(),
				session->next_receive_order++,
				session->delayed_packets);
			session->packet_changed.notify_one();
		}
		PWINDIVERT_TCPHDR tcp_header = nullptr;
		if (WinDivertHelperParsePacket(packet_data, received_length, nullptr, nullptr, nullptr, nullptr, nullptr, &tcp_header, nullptr,
										 nullptr, nullptr, nullptr, nullptr) &&
			 tcp_header != nullptr)
		{
			LOG_DEBUG("%s recv: TCP packet: Length = %u, Sequence = %u, Ack = %u, Timestamp = %lld, IsOutbound = %d, IsLoopback = %d",
					  profile_label.c_str(),
					  received_length,
					  WinDivertHelperNtohl(tcp_header->SeqNum),
					  WinDivertHelperNtohl(tcp_header->AckNum),
					  address.Timestamp,
					  address.Outbound,
					  address.Loopback);
		}
		else
		{
			LOG_DEBUG("%s recv: packet: Length = %u, Timestamp = %lld, IsOutbound = %d, IsLoopback = %d",
					  profile_label.c_str(),
					  received_length,
					  address.Timestamp,
					  address.Outbound,
					  address.Loopback);
		}
	}
}

void PacketEngine::write_packets(const std::shared_ptr<Session>& session)
{
	const ProfileOptions& profile_options = options_.profiles[session->profile - 1];
	const std::string	   profile_label	 = "profile #" + std::to_string(session->profile) + " - " + profile_options.name;
	while (!session->stopping)
	{
		while (!session->stopping)
		{
			std::vector<PacketNode*> ready_packets;
			{
				std::unique_lock<std::mutex> lock(session->packet_mutex);
				while (session->delayed_packets.empty() && !session->stopping)
					session->packet_changed.wait(lock);
				if (session->stopping)
					break;

				const uint64_t now = GetTickCount64();
				if (session->delayed_packets.top()->release_at > now)
				{
					if (session->delayed_packets.top()->release_at == (std::numeric_limits<uint64_t>::max)())
						session->packet_changed.wait(lock);
					else
					{
						const uint64_t wait_ms = session->delayed_packets.top()->release_at - now;
						session->packet_changed.wait_for(lock, std::chrono::milliseconds(wait_ms));
					}
					continue;
				}
				session->mode->release(session->delayed_packets, now, ready_packets);
			}
			for (PacketNode* node : ready_packets)
			{
				UINT sent = 0;
				if (!WinDivertSend(session->handle, node->packet, node->length, &sent, node->address))
				{
					const DWORD error = GetLastError();
					LOG_ERROR("%s send: WinDivertSend failed %lu: %s", profile_label.c_str(), error, format_win32_error(error).c_str());
				}
				else if (sent != 0)
				{
					state_->profile_stats[session->profile - 1].delayed_packets_sent.fetch_add(1);
					LOG_DEBUG("%s send: delayed packet: Length = %u, Timestamp = %llu, SendLen = %u",
							  profile_label.c_str(),
							  node->length,
							  static_cast<unsigned long long>(node->address->Timestamp),
							  sent);
				}
			}
			for (size_t index = 0; index < ready_packets.size(); ++index)
			{
				PacketNode* node = ready_packets[index];
				destroy_packet_node(node);
			}
		}

		std::vector<PacketNode*> pending_packets;
		{
			std::lock_guard<std::mutex> lock(session->packet_mutex);
			session->mode->flush(session->delayed_packets, pending_packets);
		}
		for (PacketNode* node : pending_packets)
		{
			UINT sent = 0;
			if (!WinDivertSend(session->handle, node->packet, node->length, &sent, node->address))
			{
				const DWORD error = GetLastError();
				LOG_ERROR("%s flush: WinDivertSend failed %lu: %s", profile_label.c_str(), error, format_win32_error(error).c_str());
			}
			else if (sent != 0)
			{
				state_->profile_stats[session->profile - 1].teardown_packets_sent.fetch_add(1);
				LOG_DEBUG("%s flush: sent packet: Length = %u, Timestamp = %llu, SendLen = %u",
						  profile_label.c_str(),
						  node->length,
						  static_cast<unsigned long long>(node->address->Timestamp),
						  sent);
			}
			destroy_packet_node(node);
		}
	}
	LOG_DEBUG("%s flush: stopped", profile_label.c_str());
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
	const std::string		  filter		  = server_filter(profile_options);
	UINT				  flags			  = sniff ? WINDIVERT_FLAG_SNIFF : 0;
	const std::string	  capture_filter  = outbound ? "outbound and (" + filter + ")" : filter;
	const WINDIVERT_LAYER layer			  = forward ? WINDIVERT_LAYER_NETWORK_FORWARD : WINDIVERT_LAYER_NETWORK;
	HANDLE				  handle		  = WinDivertOpen(capture_filter.c_str(), layer, 0, flags);
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
	state_->profile_stats[profile - 1].enabled_since = GetTickCount64();
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 1024);
	state_->active_sessions[profile - 1] = session;
	state_->active_profiles[profile - 1] = true;
	running_ = true;
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
			 profile_options.mode == ProfileActivationMode::hold ? "hold" : "toggle",
			 profile_options.mode == ProfileActivationMode::hold ? "Release key(s) to turn off" : "Press key(s) again to turn off");
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
		stats.enabled_time_total += enabled_time;
		if (enabled_time < stats.enabled_time_min)
			stats.enabled_time_min = enabled_time;
		if (enabled_time > stats.enabled_time_max)
			stats.enabled_time_max = enabled_time;
		++stats.enabled_count;
		state_->active_sessions[profile - 1].reset();
		state_->active_profiles[profile - 1] = false;
		running_ = std::any_of(state_->active_profiles.begin(), state_->active_profiles.end(), [](bool active) { return active; });
		session->stopping = true;
		WinDivertShutdown(session->handle, WINDIVERT_SHUTDOWN_RECV);
		session->packet_changed.notify_all();
		state_->cleanup_threads.emplace_back([this, session, enabled_time, profile] {
			session->receive_thread.join();
			session->send_thread.join();
			WinDivertClose(session->handle);
			timeEndPeriod(1);
			LOG_INFO("profile #%d - %s teardown: disabled after %s",
					 profile,
					 options_.profiles[profile - 1].name.c_str(),
					 logging::format_duration(enabled_time).c_str());
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
}

void PacketEngine::stop_workers()
{
	shutdown_ = true;
	teardown();
	for (std::thread& cleanup_thread : state_->cleanup_threads)
		if (cleanup_thread.joinable())
			cleanup_thread.join();
}