#ifndef PACKET_ENGINE_INTERNAL_H_
#define PACKET_ENGINE_INTERNAL_H_

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "packet_engine.h"
#include "platform.h"
#include "packet_backend.h"
#include "packet_headers.h"
#include "packet_engine_util.h"
#include "region_lookup.h"
#include "../modules/packet_mode.h"

/// Runtime resources and packet queues owned by one active profile.
struct PacketEngine::Session
{
	/// Creates a profile session from its index, capture channel, and packet mode.
	explicit Session(int profile_number, std::unique_ptr<backend::PacketChannel> channel, PacketMode* packet_mode)
	: profile(profile_number)
	, handle(std::move(channel))
	, mode(packet_mode)
	{
	}

	int									  profile;
	std::unique_ptr<backend::PacketChannel> handle;
	std::atomic<bool>			   stopping = false;
	std::mutex					   packet_mutex;
	std::condition_variable		   packet_changed;
	uint64_t					   next_receive_order = 0;
	PacketQueue					   delayed_packets;
	PacketMode*					   mode;
#ifdef LAGSW_FEATURE_PCAP_FILES
	PcapCapture					   pcap;
#endif
	std::thread					   receive_thread;
	std::thread					   send_thread;
};

/// Shared mutable runtime state for packet-engine workers and status queries.
struct PacketEngine::State
{
	/// Timing and packet counters for one configured profile.
	struct ProfileStats
	{
		uint64_t			  enabled_since			= 0;
		uint64_t			  enabled_time_total	= 0;
		uint64_t			  enabled_time_min		= (std::numeric_limits<uint64_t>::max)();
		uint64_t			  enabled_time_max		= 0;
		uint64_t			  last_enabled_time		= 0;
		uint64_t			  last_disabled_at		= 0;
		uint64_t			  enabled_count			= 0;
		std::atomic<uint64_t> packets_caught		= 0;
		std::atomic<uint64_t> delayed_packets_sent	= 0;
		std::atomic<uint64_t> teardown_packets_sent = 0;
	};

	/// Initializes per-profile statistics for the configured profile count.
	explicit State(size_t profile_count) : profile_stats(profile_count) {}

	std::mutex										  lifecycle_mutex;
	std::condition_variable							  lifecycle_changed;
	std::vector<bool>								  active_profiles;
	std::vector<ProfileStats>						  profile_stats;
	std::vector<std::shared_ptr<Session>>			  active_sessions;
	std::vector<std::thread>						  cleanup_threads;
	std::mutex										  region_mutex;
	std::unordered_map<std::string, std::string>	  server_regions;
	std::unordered_map<std::string, RegionCacheEntry> region_cache;
	std::unordered_set<std::string>					  region_lookups_started;
	std::vector<std::thread>						  region_threads;
	std::string										  client_region;

#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	std::unique_ptr<backend::PacketChannel>	  discovery_handle;
	std::thread								  discovery_thread;
	std::mutex								  discovery_mutex;
	std::string								  discovered_server;
	std::unordered_map<std::string, uint64_t> discovery_counts;
	bool									  authoritative_server		  = false;
	bool									  select_authoritative_server = false;
#endif
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	std::unique_ptr<backend::PacketChannel> probe_handle;
	std::thread						probe_thread;
	std::unique_ptr<backend::PacketChannel> region_enforcement_handle;
	std::thread						region_enforcement_recv_thread;
	std::thread						region_enforcement_send_thread;
	std::mutex						region_enforcement_mutex;
	std::condition_variable			region_enforcement_changed;
	std::atomic<bool>				region_enforcement_stopping = false;
	mutable std::mutex				probe_mutex;
	bool							probe_received	 = false;
	uint64_t						probe_window_end = 0;
	uint64_t						next_check_time	 = 0;
	std::unordered_set<std::string> probed_addresses_in_window;

	/// A packet buffered until its region-enforcement release time.
	struct DelayedEnforcementPacket
	{
		std::vector<uint8_t> data;
		backend::PacketMeta	 address;
		uint64_t			 release_at = 0;
	};
	std::vector<DelayedEnforcementPacket> enforcement_queue;
#endif

#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	std::unique_ptr<backend::PacketChannel> fad_handle;
	std::thread						fad_thread;
	mutable std::mutex				fad_mutex;
	std::string						fad_client_source_address;
	std::string						fad_client_destination_address;
#endif
};

#endif
