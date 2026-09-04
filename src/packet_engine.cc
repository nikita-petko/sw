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
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <mutex>
#include <queue>
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

struct PacketNode
{
	BYTE*			   packet;
	UINT			   length;
	WINDIVERT_ADDRESS* address;
	int				   profile;
	uint64_t		   release_at;
	uint64_t		   receive_order;
};

struct PacketReleaseEarlier
{
	bool operator()(const PacketNode* left, const PacketNode* right) const
	{
		if (left->release_at != right->release_at)
			return left->release_at > right->release_at;
		return left->receive_order > right->receive_order;
	}
};

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
	for (const int key : profile.keys)
	{
		if (!result.empty())
			result += "+";
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
	explicit Session(int profile_number, HANDLE divert_handle) : profile(profile_number), handle(divert_handle) {}

	int																				 profile;
	HANDLE																			 handle;
	std::atomic<bool>																 stopping = false;
	std::mutex																		 packet_mutex;
	std::condition_variable															 packet_changed;
	uint64_t																		 next_receive_order	 = 0;
	uint64_t																		 ratio_release_at	 = 0;
	int32_t																			 ratio_batch_packets = 0;
	std::priority_queue<PacketNode*, std::vector<PacketNode*>, PacketReleaseEarlier> delayed_packets;
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
	int						  current_profile = 1;
	int						  last_profile	  = 0;
	std::vector<ProfileStats> profile_stats;
	std::shared_ptr<Session>  active_session;
	std::vector<std::thread>  cleanup_threads;
};

PacketEngine::PacketEngine(PacketEngineOptions options) : options_(std::move(options)), state_(new State(options_.profiles.size()))
{
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

size_t PacketEngine::pending_packets() const
{
	std::shared_ptr<Session> session;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		session = state_->active_session;
	}
	if (!session)
		return 0;
	std::lock_guard<std::mutex> lock(session->packet_mutex);
	return session->delayed_packets.size();
}

uint64_t PacketEngine::next_batch_in_ms() const
{
	std::shared_ptr<Session> session;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		session = state_->active_session;
	}
	if (!session)
		return 0;
	std::lock_guard<std::mutex> lock(session->packet_mutex);
	if (session->delayed_packets.empty())
		return 0;

	const uint64_t now		  = GetTickCount64();
	const uint64_t release_at = session->delayed_packets.top()->release_at;
	if (release_at == (std::numeric_limits<uint64_t>::max)())
		return (std::numeric_limits<uint64_t>::max)();
	return release_at > now ? release_at - now : 0;
}

void PacketEngine::print_state() const
{
	int profile		 = 0;
	int last_profile = 0;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		profile		 = running_ ? state_->current_profile : 0;
		last_profile = state_->last_profile;
	}

	size_t	 queued_packets	 = 0;
	uint64_t next_release_in = 0;
	{
		std::shared_ptr<Session> session;
		{
			std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
			session = state_->active_session;
		}
		if (session)
		{
			std::lock_guard<std::mutex> lock(session->packet_mutex);
			queued_packets = session->delayed_packets.size();
			if (!session->delayed_packets.empty())
			{
				const uint64_t now		  = GetTickCount64();
				const uint64_t release_at = session->delayed_packets.top()->release_at;
				next_release_in			  = release_at == (std::numeric_limits<uint64_t>::max)() ? (std::numeric_limits<uint64_t>::max)()
											: release_at > now									 ? release_at - now
																								 : 0;
			}
		}
	}

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
			if (profile == static_cast<int>(profile_number))
				enabled_time_current = GetTickCount64() - stats.enabled_since;
			enabled_time_total = stats.enabled_time_total;
			enabled_time_min   = stats.enabled_count == 0 ? 0 : stats.enabled_time_min;
			enabled_time_max   = stats.enabled_time_max;
			last_enabled_time  = stats.last_enabled_time;
			enabled_count	   = stats.enabled_count;
		}
		const uint64_t enabled_time_average = enabled_count == 0 ? 0 : enabled_time_total / enabled_count;
		std::string	   profile_label		= profile_options.name;
		if (profile == static_cast<int>(profile_number))
			profile_label += " (ACTIVE)";
		else if (enabled_count != 0)
			profile_label += " (held " + logging::format_duration(last_enabled_time) + ")";
		LOG_INFO("%s", format_state_divider(state_width, profile_label).c_str());
		log_state_line(state_width,
					   "profile:         #" + std::to_string(profile_number) + " - " + profile_options.name +
						   (last_profile == static_cast<int>(profile_number) && profile == 0 ? " (last)" : ""));
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
	while (!session->stopping)
	{
		BYTE			  packet_data[0xFFFF];
		WINDIVERT_ADDRESS address;
		UINT			  received_length = 0;
		if (!WinDivertRecv(session->handle, packet_data, sizeof(packet_data), &received_length, &address))
		{
			const DWORD error = GetLastError();
			if (!session->stopping && error != ERROR_INVALID_HANDLE && error != ERROR_OPERATION_ABORTED)
				LOG_ERROR("WinDivertRecv error %lu: %s", error, format_win32_error(error).c_str());
			continue;
		}
		state_->profile_stats[profile - 1].packets_caught.fetch_add(1);
		const bool sniff = profile_options.windivert_options.sniff.value_or(false);
		if (!sniff)
		{
			std::lock_guard<std::mutex> lock(session->packet_mutex);
			if (session->stopping)
				break;
			const int32_t  configured_delay = profile_options.delay_ms;
			const uint64_t now				= GetTickCount64();
			PacketNode*	   node				= new PacketNode;
			node->packet					= new BYTE[received_length];
			node->length					= received_length;
			node->address					= new WINDIVERT_ADDRESS(address);
			node->profile					= state_->current_profile;	// Record the active profile
			node->release_at =
				configured_delay <= 0 ? (std::numeric_limits<uint64_t>::max)() : now + static_cast<uint64_t>(configured_delay);
			node->receive_order = session->next_receive_order++;
			if (profile_options.delay_mode == PacketDelayMode::send_all_after_delay && !session->delayed_packets.empty())
				node->release_at = session->delayed_packets.top()->release_at;
			else if (profile_options.delay_mode == PacketDelayMode::ratio)
			{
				if (session->delayed_packets.empty())
				{
					session->ratio_release_at	 = now + static_cast<uint64_t>(configured_delay);
					session->ratio_batch_packets = 0;
				}
				else if (!profile_options.ratio_percent && session->ratio_batch_packets >= profile_options.ratio)
				{
					session->ratio_release_at += static_cast<uint64_t>(configured_delay);
					session->ratio_batch_packets = 0;
				}
				node->release_at = session->ratio_release_at;
				if (!profile_options.ratio_percent)
					++session->ratio_batch_packets;
			}
			std::memcpy(node->packet, packet_data, received_length);
			session->delayed_packets.push(node);
			session->packet_changed.notify_one();
		}
		LOG_DEBUG("Received packet: Length = %u, Timestamp = %lld, IsOutbound = %d, IsLoopback = %d",
				  received_length,
				  address.Timestamp,
				  address.Outbound,
				  address.Loopback);
	}
}

void PacketEngine::write_packets(const std::shared_ptr<Session>& session)
{
	const ProfileOptions& profile_options = options_.profiles[session->profile - 1];
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
				const ProfileOptions& profile = profile_options;
				if (profile.delay_mode == PacketDelayMode::ratio && profile.ratio_percent)
				{
					std::vector<PacketNode*> queued_packets;
					while (!session->delayed_packets.empty())
					{
						PacketNode* node = session->delayed_packets.top();
						session->delayed_packets.pop();
						if (node == nullptr || node->address == nullptr)
						{
							delete node;
							continue;
						}
						queued_packets.push_back(node);
					}
					const size_t send_count =
						(std::max<size_t>)(1, (queued_packets.size() * static_cast<size_t>(profile.ratio) + 99) / 100);
					session->ratio_release_at = now + static_cast<uint64_t>(profile.delay_ms);
					for (size_t index = 0; index < queued_packets.size(); ++index)
					{
						PacketNode* node = queued_packets[index];
						if (index < send_count)
							ready_packets.push_back(node);
						else
						{
							node->release_at = session->ratio_release_at;
							session->delayed_packets.push(node);
						}
					}
				}
				else
					while (!session->delayed_packets.empty())
					{
						PacketNode* node = session->delayed_packets.top();
						if (node == nullptr || node->address == nullptr)
						{
							session->delayed_packets.pop();
							delete node;
							continue;
						}
						if (node->release_at > now)
							break;
						session->delayed_packets.pop();
						ready_packets.push_back(node);
					}
			}
			for (PacketNode* node : ready_packets)
			{
				UINT sent = 0;
				if (!WinDivertSend(session->handle, node->packet, node->length, &sent, node->address))
				{
					const DWORD error = GetLastError();
					LOG_ERROR("WinDivertSend failed %lu: %s", error, format_win32_error(error).c_str());
				}
				else if (sent != 0)
				{
					state_->profile_stats[session->profile - 1].delayed_packets_sent.fetch_add(1);
					LOG_DEBUG("Sent delayed packet: Length = %u, Timestamp = %llu, SendLen = %u",
							  node->length,
							  static_cast<unsigned long long>(node->address->Timestamp),
							  sent);
				}
			}
			for (size_t index = 0; index < ready_packets.size(); ++index)
			{
				PacketNode* node = ready_packets[index];
				delete[] node->packet;
				delete node->address;
				delete node;
			}
		}

		std::vector<PacketNode*> pending_packets;
		{
			std::lock_guard<std::mutex> lock(session->packet_mutex);
			while (!session->delayed_packets.empty())
			{
				pending_packets.push_back(session->delayed_packets.top());
				session->delayed_packets.pop();
			}
		}
		for (PacketNode* node : pending_packets)
		{
			UINT sent = 0;
			if (!WinDivertSend(session->handle, node->packet, node->length, &sent, node->address))
			{
				const DWORD error = GetLastError();
				LOG_ERROR("WinDivertSend failed %lu: %s", error, format_win32_error(error).c_str());
			}
			else if (sent != 0)
			{
				state_->profile_stats[session->profile - 1].teardown_packets_sent.fetch_add(1);
				LOG_DEBUG("Sent flushed packet: Length = %u, Timestamp = %llu, SendLen = %u",
						  node->length,
						  static_cast<unsigned long long>(node->address->Timestamp),
						  sent);
			}
			delete[] node->packet;
			delete node->address;
			delete node;
		}
	}
	LOG_DEBUG("Packet flush stopped");
}

void PacketEngine::setup(int profile)
{
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	if (running_)
		return;
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
	{
		LOG_ERROR("Profile %d is not configured", profile);
		return;
	}
	state_->current_profile = profile;
	timeBeginPeriod(1);
	const ProfileOptions& profile_options = options_.profiles[profile - 1];
	const bool			  sniff			  = profile_options.windivert_options.sniff.value_or(false);
	const bool			  outbound		  = profile_options.windivert_options.outbound.value_or(false);
	const bool			  forward		  = profile_options.windivert_options.forward.value_or(false);
	const std::string&	  filter		  = profile_options.filter.value_or(options_.global_filter);
	UINT				  flags			  = sniff ? WINDIVERT_FLAG_SNIFF : 0;
	const std::string	  capture_filter  = outbound ? "outbound and (" + filter + ")" : filter;
	const WINDIVERT_LAYER layer			  = forward ? WINDIVERT_LAYER_NETWORK_FORWARD : WINDIVERT_LAYER_NETWORK;
	HANDLE				  handle		  = WinDivertOpen(capture_filter.c_str(), layer, 0, flags);
	if (handle == INVALID_HANDLE_VALUE)
	{
		const DWORD error = GetLastError();
		LOG_ERROR("Failed to open WinDivert handle %lu: %s", error, format_win32_error(error).c_str());
		timeEndPeriod(1);
		return;
	}
	std::shared_ptr<Session> session(new Session(profile, handle));
	state_->last_profile							 = profile;
	state_->profile_stats[profile - 1].enabled_since = GetTickCount64();
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 1024);
	state_->active_session	= session;
	running_				= true;
	session->receive_thread = std::thread(&PacketEngine::read_packets, this, session);
	session->send_thread	= std::thread(&PacketEngine::write_packets, this, session);
	LOG_DEBUG("Setting up...");
	LOG_DEBUG("WinDivert layer = %s, filter = %s", forward ? "NETWORK_FORWARD" : "NETWORK", capture_filter.c_str());
	LOG_INFO("Lag switch enabled, profile = %s (%s, mode = %s). %s",
			 profile_options.name.c_str(),
			 format_keys(profile_options).c_str(),
			 profile_options.mode == ProfileActivationMode::hold ? "hold" : "toggle",
			 profile_options.mode == ProfileActivationMode::hold ? "Release key(s) to turn off" : "Press key(s) again to turn off");
}

void PacketEngine::teardown()
{
	LOG_DEBUG("Teardown requested");
	uint64_t				 enabled_time = 0;
	std::shared_ptr<Session> session;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		session = state_->active_session;
		if (!session)
			return;
		LOG_DEBUG("Tearing down...");
		State::ProfileStats& stats = state_->profile_stats[state_->current_profile - 1];
		enabled_time			   = GetTickCount64() - stats.enabled_since;
		stats.last_enabled_time	   = enabled_time;
		stats.enabled_time_total += enabled_time;
		if (enabled_time < stats.enabled_time_min)
			stats.enabled_time_min = enabled_time;
		if (enabled_time > stats.enabled_time_max)
			stats.enabled_time_max = enabled_time;
		++stats.enabled_count;
		running_ = false;
		state_->active_session.reset();
		session->stopping = true;
		WinDivertShutdown(session->handle, WINDIVERT_SHUTDOWN_RECV);
		session->packet_changed.notify_all();
		state_->cleanup_threads.emplace_back([this, session, enabled_time] {
			session->receive_thread.join();
			session->send_thread.join();
			WinDivertClose(session->handle);
			timeEndPeriod(1);
			LOG_INFO("Lag switch disabled after %s", logging::format_duration(enabled_time).c_str());
		});
	}
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