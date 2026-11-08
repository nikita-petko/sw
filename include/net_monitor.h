#ifndef NET_MONITOR_H_
#define NET_MONITOR_H_

#include <atomic>
#include <chrono>
#include <deque>
#include <fstream>
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
/// that covers every known server, including the ones added by server discovery while the view is open.
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
	/// Handles a key while the view is shown: the configured pause key pauses/resumes the measurement, the reset key resets the
	/// statistics, the flows key switches between the overview and the per-flow view, the profiles key between the overview
	/// and the per-profile view, Up/Down select a flow and the export key exports the measured window (defaults: space, r,
	/// f, p, e). Returns whether the key was used by the view.
	bool handle_key(int key);

#ifdef LAGSW_NET_MONITOR_TESTING
public:
#else
private:
#endif
	/// The screen that is shown.
	enum class View
	{
		overview,
		flows,
		profiles,
	};

	/// What the network did over a number of measured seconds; used to compare the seconds a profile was active with
	/// the seconds no profile was.
	struct Conditions
	{
		uint64_t ticks		  = 0;
		double	 rtt_sum_ms	  = 0;
		uint64_t rtt_samples  = 0;
		uint64_t data_packets = 0;
		uint64_t retransmits  = 0;
		uint64_t bytes_down	  = 0;
		void	 add(const Conditions& other);
	};

	/// What was measured for one profile since the view opened or was reset.
	struct ProfileStats
	{
		uint64_t   activations	 = 0;
		uint64_t   current_ticks = 0;  // seconds of the activation that is running now
		uint64_t   last_ticks	 = 0;  // seconds of the last finished activation
		uint64_t   longest_ticks = 0;
		Conditions active;			   // the seconds this profile was active in
	};

	/// The conditions that can raise an alert for a server.
	enum AlertKind
	{
		alert_rtt,
		alert_jitter,
		alert_retransmit,
		alert_stall,
		alert_kinds,
	};

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

	/// Per-second history of one flow; only kept for the flow that is selected in the flow view.
	struct FlowDetail
	{
		Series bps_down, bps_up, rtt;
	};

	/// One TCP connection or UDP exchange of a server, identified by the client and server port.
	struct Flow
	{
		std::deque<PendingSegment> pending;
		uint32_t				   highest_out_end = 0;
		uint32_t				   highest_in_end  = 0;
		bool					   tcp			   = true;
		bool					   out_seen		   = false;
		bool					   in_seen		   = false;
		bool					   syn_pending	   = false;
		bool					   closed		   = false;
		bool					   reset		   = false;
		bool					   fin_out		   = false;
		bool					   fin_in		   = false;
		bool					   ack_out_seen	   = false;
		bool					   ack_in_seen	   = false;
		uint32_t				   last_ack_out	   = 0;
		uint32_t				   last_ack_in	   = 0;
		uint16_t				   client_port	   = 0;
		uint16_t				   server_port	   = 0;
		uint64_t				   packets_up	   = 0;
		uint64_t				   packets_down	   = 0;
		uint64_t				   bytes_up		   = 0;
		uint64_t				   bytes_down	   = 0;
		uint64_t				   bytes_up_tick   = 0;
		uint64_t				   bytes_down_tick = 0;
		uint64_t				   rtt_samples	   = 0;
		double					   rtt_sum_ms	   = 0;
		double					   last_rtt_ms	   = 0;
		double					   rtt_tick_sum_ms = 0;
		uint32_t				   rtt_tick_count  = 0;
		std::chrono::steady_clock::time_point syn_sent;
		std::chrono::steady_clock::time_point first_seen;
		std::chrono::steady_clock::time_point last_seen;
		std::chrono::steady_clock::time_point closed_at;
		std::shared_ptr<FlowDetail> detail;
	};

	/// Something worth remembering about the measurement: a profile switching on or off, or an alert.
	struct Event
	{
		enum class Level
		{
			info,
			alert,
			ok,
		};
		uint64_t	tick = 0;
		Level		level = Level::info;
		std::string text;
	};

	/// Identifies a flow across frames: the server address and the flow key.
	struct FlowId
	{
		std::string address;
		uint64_t	key = 0;
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
		uint64_t	data_prev		 = 0;
		double		tick_rtt_min_ms	 = 0;
		double		tick_rtt_max_ms	 = 0;
		double		tick_max_gap_ms	 = 0;
		static constexpr size_t kRttBuckets = 6;
		uint64_t	rtt_hist[kRttBuckets] = {};
		bool		alert_active[alert_kinds] = {};
		uint64_t	alert_count[alert_kinds]  = {};
		std::deque<double> recent_rtt;
		std::map<uint64_t, Flow> flows;
		std::chrono::steady_clock::time_point last_in;
		std::chrono::steady_clock::time_point last_out;
		bool		has_in	= false;
		bool		has_silence = false;
		bool		has_out = false;
		Series		pps_up, pps_down, bps_up, bps_down, rtt, rtt_min, rtt_max, retrans, data_pkts, flows_new, score;
	};

	void capture_loop();
	void render_loop();
	void record(const uint8_t* packet, uint32_t length);
	void tick();
	void reset_locked();
	void clear_transient_locked();
	/// Opens the sniff channel for the servers known to the engine and starts the capture thread. Returns false with `error` set on failure.
	bool start_capture(std::string& error);
	/// Stops the capture thread and closes the channel.
	void stop_capture();
	/// Adds servers that the engine learned about since the last call and restarts the capture so their traffic is seen.
	void refresh_servers();
	/// Registers a server for measurement. Requires mutex_.
	void add_server_locked(const ServerOptions& server);
	/// Checks the alert thresholds of one server at the end of a tick. Requires mutex_.
	void evaluate_alerts_locked(const std::string& label, ServerStats& stats);
	void raise_alert_locked(const std::string& label, ServerStats& stats, AlertKind kind, bool exceeded, const std::string& detail);
	void add_event_locked(Event::Level level, const std::string& text);
	/// Notes profile activations and deactivations and attributes the measured second `sample` to the profiles that were
	/// active during it. Requires mutex_.
	void track_profiles_locked(const Conditions& sample);
	/// Every flow of every server, active ones first. Requires mutex_.
	struct FlowRef
	{
		std::string		   address;
		const ServerStats* stats = nullptr;
		uint64_t		   key	 = 0;
		const Flow*		   flow	 = nullptr;
	};
	std::vector<FlowRef> sorted_flows_locked() const;
	void move_flow_selection_locked(int delta);
	/// Writes the measured window to a CSV and a JSON file and returns a one-line result for the status area. Requires mutex_.
	std::string export_snapshot_locked();
	/// Appends the latest second (and new events) to the log file. Requires mutex_.
	void write_log_locked();
	/// Opens the log file configured for the view; failures are reported in the status area.
	void open_log();
	void close_log();
	/// Logs how often each server raised an alert while the view was open.
	void log_alert_summary();
	/// Lays the view out for a console of the given size (0 when unknown).
	std::string render_frame(int console_columns, int console_rows);
	/// The per-flow screen.
	std::string render_flow_view(int console_columns, int console_rows);
	/// The per-profile screen.
	std::string render_profile_view(int console_columns, int console_rows);
	/// The first lines shared by every screen.
	std::string render_header(size_t width, std::vector<std::string>& warnings);

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
	Series								  profile_active_, alerts_active_;
	std::vector<bool>					  profile_state_;
	std::vector<ProfileStats>			  profile_stats_;
	Conditions							  baseline_;  // the seconds in which no profile was active
	std::deque<Event>					  events_;
	View								  view_				  = View::overview;
	bool								  has_selection_	  = false;
	FlowId								  selection_;
	platform::SystemCounters			  system_prev_;
	bool								  system_has_prev_			= false;
	double								  peak_pps_					= 0;
	double								  sum_pps_					= 0;
	uint64_t							  peak_queued_				= 0;
	ServerStats							  total_;
	uint64_t							  total_packets_	  = 0;
	uint64_t							  other_packets_	  = 0;
	uint64_t							  unparsed_packets_	  = 0;
	uint64_t							  capture_errors_	  = 0;
	std::chrono::steady_clock::time_point paused_at_;
	std::chrono::steady_clock::time_point last_tick_;
	uint64_t							  elapsed_ticks_	  = 0;
	std::string							  open_error_;
	std::chrono::steady_clock::time_point retry_at_;
	std::string							  capture_description_;
	std::string							  status_message_;
	std::chrono::steady_clock::time_point status_until_;
	std::ofstream						  log_stream_;
};

#endif  // LAGSW_FEATURE_NET_MONITOR

#endif
