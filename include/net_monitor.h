#ifndef NET_MONITOR_H_
#define NET_MONITOR_H_

#include <atomic>
#include <chrono>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "packet_backend.h"
#include "packet_engine.h"
#include "platform.h"

#ifdef LAGSW_FEATURE_NET_MONITOR

/// Full-screen network statistics view (see pocs/net_monitor.md). Nothing is captured or rendered until toggle()
/// switches the view on; leaving the view stops both again. Statistics are measured passively from a sniff channel
/// that covers every configured server.
class NetMonitor
{
public:
	/// Both arguments must outlive the object.
	NetMonitor(const PacketEngine& engine, const PacketEngineOptions& options);
	/// Leaves the view if it is still shown.
	~NetMonitor();

	NetMonitor(const NetMonitor&)			 = delete;
	NetMonitor& operator=(const NetMonitor&) = delete;

	/// Enters or leaves the view. Call from the thread that reads the keyboard.
	void toggle();
	/// Leaves the view if shown.
	void stop();
	/// Whether `key` is the configured key that opens and closes the view.
	bool is_toggle_key(int key) const;
	/// Whether the view is currently shown.
	bool active() const { return active_; }
	/// Handles a key while the view is shown: space pauses/resumes the measurement, 'r' resets the statistics.
	void handle_key(int key);

private:
	/// A bounded history of per-second samples for the sparklines.
	struct Series
	{
		std::deque<double> values;
		void			   push(double value);
	};

	/// Smoothed per-second counters of one direction.
	struct Direction
	{
		uint64_t packets	  = 0;
		uint64_t bytes		  = 0;
		uint64_t packets_tick = 0;
		uint64_t bytes_tick	  = 0;
	};

	/// A TCP data segment that has not been acknowledged yet.
	struct PendingSegment
	{
		uint32_t							  end_seq;
		std::chrono::steady_clock::time_point sent;
	};

	struct Flow
	{
		std::deque<PendingSegment> pending;
		uint32_t				   highest_out_end = 0;
		uint32_t				   highest_in_end  = 0;
		bool					   out_seen		   = false;
		bool					   in_seen		   = false;
		bool					   syn_pending	   = false;
		bool					   closed		   = false;
		bool					   fin_out		   = false;
		bool					   fin_in		   = false;
		bool					   ack_out_seen	   = false;
		bool					   ack_in_seen	   = false;
		uint32_t				   last_ack_out	   = 0;
		uint32_t				   last_ack_in	   = 0;
		std::chrono::steady_clock::time_point syn_sent;
	};

	/// Traffic towards one server port (TCP or UDP), summed over all configured servers.
	struct PortStats
	{
		bool		tcp = false;
		uint16_t	port = 0;
		Direction	up;
		Direction	down;
		uint64_t	rtt_samples		= 0;
		double		rtt_sum_ms		= 0;
		double		last_rtt_ms		= 0;
		double		tick_rtt_sum_ms = 0;
		uint32_t	tick_rtt_count	= 0;
		double		pkts_up	  = 0;  // packets in the last second
		double		pkts_down = 0;
		double		rate_up	  = 0;  // bytes in the last second
		double		rate_down = 0;
		Series		pps, rtt;
	};

	/// Everything measured for one server.
	struct ServerStats
	{
		std::string label;
		Direction	up;
		Direction	down;
		uint64_t	tcp_packets		 = 0;
		uint64_t	udp_packets		 = 0;
		uint64_t	retrans_up		 = 0;
		uint64_t	retrans_down	 = 0;
		uint64_t	data_up			 = 0;
		uint64_t	data_down		 = 0;
		uint64_t	resets			 = 0;
		uint64_t	syn_packets		 = 0;
		uint64_t	fin_packets		 = 0;
		uint64_t	psh_packets		 = 0;
		uint64_t	pure_acks		 = 0;
		uint64_t	dup_acks_up		 = 0;  // duplicate ACKs we sent: the server's data is arriving with holes
		uint64_t	dup_acks_down	 = 0;  // duplicate ACKs the server sent: our data is arriving with holes
		uint64_t	zero_windows	 = 0;
		uint64_t	flows_opened	 = 0;
		uint64_t	flows_tick		 = 0;
		uint64_t	stalls			 = 0;  // inbound gaps of at least kStallMs
		uint64_t	ecn_marked		 = 0;
		uint64_t	dscp_changes	 = 0;
		uint64_t	ttl_changes		 = 0;
		int			last_ttl		 = -1;
		int			last_dscp		 = -1;
		uint64_t	handshakes		 = 0;
		uint64_t	syn_retries		 = 0;
		double		handshake_sum_ms = 0;
		double		handshake_min_ms = 0;
		double		handshake_max_ms = 0;
		double		last_handshake_ms = 0;
		uint64_t	rtt_samples		 = 0;
		double		rtt_sum_ms		 = 0;
		double		rtt_min_ms		 = 0;
		double		rtt_max_ms		 = 0;
		double		last_rtt_ms		 = 0;
		double		jitter_ms		 = 0;
		double		tick_rtt_sum_ms	 = 0;
		uint32_t	tick_rtt_count	 = 0;
		double		interarrival_jitter_ms = 0;
		double		max_gap_ms		 = 0;
		double		prev_gap_ms		 = 0;
		uint64_t	retrans_prev	 = 0;
		std::deque<double> recent_rtt;
		std::map<uint64_t, Flow> flows;
		std::chrono::steady_clock::time_point last_in;
		std::chrono::steady_clock::time_point last_out;
		bool		has_in	= false;
		bool		has_out = false;
		Series		pps_up, pps_down, bps_up, bps_down, rtt, retrans, flows_new, score;
	};

	void capture_loop();
	void render_loop();
	void record(const uint8_t* packet, uint32_t length);
	void tick();
	void reset_locked();
	void clear_transient_locked();
	/// Lays the view out for a console of the given size (0 when unknown).
	std::string render_frame(int console_columns, int console_rows);

	const PacketEngine&		   engine_;
	const PacketEngineOptions& options_;

	bool				active_ = false;
	std::atomic<bool>	paused_ = false;
	std::atomic<bool>	stopping_ = false;
	std::atomic<bool>	reset_requested_ = false;

	std::unique_ptr<backend::PacketChannel> channel_;
	std::thread								capture_thread_;
	std::thread								render_thread_;

	std::mutex							  mutex_;
	std::map<std::string, ServerStats>	  servers_;
	std::vector<std::string>			  server_order_;
	std::map<uint32_t, PortStats>		  ports_;
	static constexpr size_t				  kSizeBuckets = 4;
	uint64_t							  size_up_[kSizeBuckets]	= {};
	uint64_t							  size_down_[kSizeBuckets]	= {};
	double								  peak_bps_up_				= 0;
	double								  peak_bps_down_			= 0;
	Series								  queued_;
	Series								  cpu_, nic_problems_;
	platform::SystemCounters			  system_prev_;
	bool								  system_has_prev_			= false;
	double								  peak_pps_					= 0;
	double								  sum_pps_					= 0;
	uint64_t							  peak_queued_				= 0;
	ServerStats							  total_;
	uint64_t							  total_packets_	  = 0;
	uint64_t							  other_packets_	  = 0;
	std::chrono::steady_clock::time_point paused_at_;
	std::chrono::steady_clock::time_point last_tick_;
	uint64_t							  elapsed_ticks_	  = 0;
	std::string							  open_error_;
};

#endif  // LAGSW_FEATURE_NET_MONITOR

#endif
