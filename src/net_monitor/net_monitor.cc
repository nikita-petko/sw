// Lifecycle of the net monitor: entering and leaving the view, the capture channel, key handling and resets.
#include "net_monitor.h"

#ifdef LAGSW_FEATURE_NET_MONITOR

#	include <algorithm>

#	include "internal.h"
#	include "log.h"
#	include "platform.h"

LOG_DEFAULT_GROUP(logging::group::backend)

using namespace net_monitor_detail;

void NetMonitor::Series::push(double value)
{
	values.push_back(value);
	if (values.size() > kHistory)
		values.pop_front();
}

void NetMonitor::Conditions::add(const Conditions& other)
{
	ticks += other.ticks;
	rtt_sum_ms += other.rtt_sum_ms;
	rtt_samples += other.rtt_samples;
	data_packets += other.data_packets;
	retransmits += other.retransmits;
	bytes_down += other.bytes_down;
}

NetMonitor::NetMonitor(const PacketEngine& engine, const PacketEngineOptions& options) : engine_(engine), options_(options)
{
}

NetMonitor::~NetMonitor()
{
	stop();
}

bool NetMonitor::is_toggle_key(int key) const
{
	return options_.features.net_monitor.enabled && normalize_key(key) == normalize_key(options_.features.net_monitor.key);
}

void NetMonitor::toggle()
{
	if (active_)
	{
		stop();
		return;
	}

	const std::vector<ServerOptions> servers = engine_.servers();
	if (servers.empty())
	{
		LOG_WARN("Net monitor: no servers are configured, there is nothing to measure.");
		return;
	}

	{
		std::lock_guard<std::mutex> lock(mutex_);
		servers_.clear();
		server_order_.clear();
		for (const ServerOptions& server : servers)
			add_server_locked(server);
		reset_locked();
		view_		   = View::overview;
		has_selection_ = false;
		status_message_.clear();
		open_error_.clear();
	}
	std::string open_error;
	if (!start_capture(open_error))
	{
		LOG_ERROR("Net monitor: failed to open the capture channel: %s", open_error.c_str());
		return;
	}
	paused_			 = false;
	stopping_		 = false;
	reset_requested_ = false;
	retry_at_		 = Clock::now();
	open_log();

	logging::set_suspended(true);
	std::printf("\033[?1049h\033[?25l");
	std::fflush(stdout);
	active_		   = true;
	render_thread_ = std::thread(&NetMonitor::render_loop, this);
}

void NetMonitor::stop()
{
	if (!active_)
		return;
	// The render thread may be restarting the capture, so it has to be gone before the capture is torn down.
	stopping_ = true;
	if (render_thread_.joinable())
		render_thread_.join();
	stop_capture();
	close_log();
	active_ = false;
	std::printf("\033[?25h\033[?1049l");
	std::fflush(stdout);
	logging::set_suspended(false);
	log_alert_summary();
}

bool NetMonitor::start_capture(std::string& error)
{
	std::vector<std::string> addresses;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		addresses = server_order_;
	}
	backend::ProfileFilter spec;
	spec.user_filter		= "tcp or udp";
	spec.include_bare_acks	= true;
	spec.client_enforcement = backend::ClientAddressEnforcement::none;
	spec.server_direction	= backend::ServerDirection::both;
	spec.server_addresses	= addresses;

	backend::OpenOptions open_options;
	open_options.filter			 = backend::filters::profile(spec);
	open_options.sniff			 = true;
	open_options.priority		 = backend::priority::net_monitor;
	open_options.include_forward = true;
	channel_					 = backend::open(open_options, error);
	if (!channel_)
		return false;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		capture_description_ = channel_->description();
	}
	capture_thread_ = std::thread(&NetMonitor::capture_loop, this);
	return true;
}

void NetMonitor::stop_capture()
{
	if (channel_)
		channel_->shutdown_recv();
	if (capture_thread_.joinable())
		capture_thread_.join();
	if (channel_)
	{
		channel_->close();
		channel_.reset();
	}
}

void NetMonitor::add_server_locked(const ServerOptions& server)
{
	if (servers_.count(server.address))
		return;
	servers_[server.address].label = server.name.empty() || server.name == server.address ? server.address : server.name;
	server_order_.push_back(server.address);
}

void NetMonitor::refresh_servers()
{
	const std::vector<ServerOptions> known = engine_.servers();
	std::vector<std::string>		 added;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		for (const ServerOptions& server : known)
			if (!servers_.count(server.address))
			{
				add_server_locked(server);
				added.push_back(server.address);
			}
		for (const std::string& address : added)
			add_event_locked(Event::Level::info, "server " + address + " was discovered and is now monitored");
	}
	// A failed restart is retried, so a capture that could not be reopened does not stay dead.
	const bool retry = !channel_ && Clock::now() >= retry_at_;
	if (added.empty() && !retry)
		return;
	stop_capture();
	std::string error;
	const bool	started = start_capture(error);
	retry_at_			= Clock::now() + kCaptureRetry;
	std::lock_guard<std::mutex> lock(mutex_);
	if (started)
		open_error_.clear();
	else
	{
		open_error_ = "capture restart failed: " + error;
		if (!added.empty())
			add_event_locked(Event::Level::alert, open_error_);
	}
}

bool NetMonitor::handle_key(int key)
{
	const int				 upper	 = normalize_key(key);
	const NetMonitorOptions& monitor = options_.features.net_monitor;
	const auto				 matches = [upper](int configured) { return upper == normalize_key(configured); };
	if (matches(monitor.pause_key))
	{
		if (paused_)
		{
			// Measurements taken before the pause must not be paired with packets seen after it.
			std::lock_guard<std::mutex> lock(mutex_);
			const auto resumed_at = Clock::now();
			for (auto& entry : servers_)
				if (entry.second.has_silence)
					entry.second.last_in += resumed_at - paused_at_;
			clear_transient_locked();
			last_tick_		 = resumed_at;
			system_has_prev_ = false;
			paused_			 = false;
		}
		else
		{
			std::lock_guard<std::mutex> lock(mutex_);
			paused_at_ = Clock::now();
			paused_	   = true;
		}
		return true;
	}
	if (matches(monitor.reset_key))
	{
		reset_requested_ = true;
		return true;
	}
	if (matches(monitor.flows_key))
	{
		std::lock_guard<std::mutex> lock(mutex_);
		view_ = view_ == View::flows ? View::overview : View::flows;
		if (view_ == View::flows && !has_selection_)
			move_flow_selection_locked(0);
		return true;
	}
	if (matches(monitor.profiles_key))
	{
		std::lock_guard<std::mutex> lock(mutex_);
		view_ = view_ == View::profiles ? View::overview : View::profiles;
		return true;
	}
	if (matches(monitor.export_key))
	{
		std::lock_guard<std::mutex> lock(mutex_);
		status_message_ = export_snapshot_locked();
		status_until_	= Clock::now() + kStatusLifetime;
		return true;
	}
	if ((key == platform::key::up || key == platform::key::down) && view_ == View::flows)
	{
		std::lock_guard<std::mutex> lock(mutex_);
		move_flow_selection_locked(key == platform::key::up ? -1 : 1);
		return true;
	}
	return false;
}

std::vector<NetMonitor::FlowRef> NetMonitor::sorted_flows_locked() const
{
	std::vector<FlowRef> flows;
	for (const std::string& address : server_order_)
	{
		const ServerStats& stats = servers_.at(address);
		for (const auto& entry : stats.flows)
			flows.push_back({address, &stats, entry.first, &entry.second});
	}
	std::stable_sort(flows.begin(), flows.end(), [](const FlowRef& a, const FlowRef& b) {
		if (a.flow->closed != b.flow->closed)
			return !a.flow->closed;
		return a.flow->first_seen > b.flow->first_seen;
	});
	return flows;
}

void NetMonitor::move_flow_selection_locked(int delta)
{
	const std::vector<FlowRef> flows = sorted_flows_locked();
	if (flows.empty())
	{
		has_selection_ = false;
		return;
	}
	Flow*  previous = nullptr;
	FlowId previous_id;
	if (has_selection_)
	{
		const auto server = servers_.find(selection_.address);
		if (server != servers_.end())
		{
			const auto flow = server->second.flows.find(selection_.key);
			if (flow != server->second.flows.end())
				previous = &flow->second;
		}
		previous_id = selection_;
	}
	size_t index = 0;
	for (size_t i = 0; i < flows.size(); ++i)
		if (has_selection_ && flows[i].address == selection_.address && flows[i].key == selection_.key)
			index = i;
	if (delta < 0 && index > 0)
		--index;
	else if (delta > 0 && index + 1 < flows.size())
		++index;
	selection_	   = {flows[index].address, flows[index].key};
	has_selection_ = true;
	// The history of a flow is only kept while it is selected, so it starts with the selection and ends when it is left.
	if (previous && (previous_id.address != selection_.address || previous_id.key != selection_.key))
		previous->detail.reset();
	Flow& selected = servers_[selection_.address].flows[selection_.key];
	if (!selected.detail)
		selected.detail = std::make_shared<FlowDetail>();
}

void NetMonitor::reset_locked()
{
	for (auto& entry : servers_)
	{
		const std::string label = entry.second.label;
		entry.second			= ServerStats{};
		entry.second.label		= label;
	}
	total_ = ServerStats{};
	ports_.clear();
	std::fill(std::begin(size_up_), std::end(size_up_), 0);
	std::fill(std::begin(size_down_), std::end(size_down_), 0);
	peak_bps_up_	  = 0;
	peak_bps_down_	  = 0;
	peak_pps_		  = 0;
	sum_pps_		  = 0;
	queued_			  = Series{};
	peak_queued_	  = 0;
	cpu_			  = Series{};
	nic_problems_	  = Series{};
	system_has_prev_  = false;
	total_packets_	  = 0;
	other_packets_	  = 0;
	unparsed_packets_ = 0;
	capture_errors_	  = 0;
	profile_active_	  = Series{};
	alerts_active_	  = Series{};
	events_.clear();
	has_selection_ = false;
	profile_state_.assign(options_.profiles.size(), false);
	for (size_t i = 0; i < profile_state_.size(); ++i)
		profile_state_[i] = engine_.is_running(static_cast<int>(i) + 1);
	profile_stats_.assign(options_.profiles.size(), ProfileStats{});
	baseline_	   = Conditions{};
	elapsed_ticks_ = 0;
	last_tick_	   = Clock::now();
}

void NetMonitor::clear_transient_locked()
{
	for (auto& entry : servers_)
	{
		entry.second.flows.clear();
		entry.second.has_in	 = false;
		entry.second.has_out = false;
	}
}

#endif	// LAGSW_FEATURE_NET_MONITOR
