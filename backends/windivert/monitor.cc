#include "monitor.h"

#ifdef LAGSW_FEATURE_BACKEND_MONITOR

#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <mutex>
#include <vector>

#include "log.h"

LOG_DEFAULT_GROUP(logging::group::windivert_monitor)

namespace wd {

struct Totals
{
	uint64_t handles = 0, received = 0, sent = 0, recv_errors = 0, send_errors = 0, queued = 0;
	int64_t	 max_lag_us = 0;
};

/// The live channels and the totals of the ones that are gone.
struct Registry
{
	std::mutex				   mutex;
	std::vector<ChannelStats*> channels;
	uint64_t				   received = 0, sent = 0, recv_errors = 0, send_errors = 0;

	static Registry& get()
	{
		static Registry registry;
		return registry;
	}

	Totals collect()
	{
		std::lock_guard<std::mutex> lock(mutex);
		Totals						totals;
		totals.received	   = received;
		totals.sent		   = sent;
		totals.recv_errors = recv_errors;
		totals.send_errors = send_errors;
		for (ChannelStats* channel : channels)
		{
			totals.received += channel->received_.load();
			totals.sent += channel->sent_.load();
			totals.recv_errors += channel->recv_errors_.load();
			totals.send_errors += channel->send_errors_.load();
			totals.queued += channel->queued_.load();
			// Only the peak since the previous sample is of interest
			totals.max_lag_us = std::max(totals.max_lag_us, channel->max_lag_us_.exchange(0));
			if (channel->is_handle_)
				++totals.handles;
		}
		return totals;
	}
};

ChannelStats::ChannelStats(bool is_handle) : is_handle_(is_handle)
{
	Registry&					registry = Registry::get();
	std::lock_guard<std::mutex> lock(registry.mutex);
	registry.channels.push_back(this);
}

ChannelStats::~ChannelStats()
{
	Registry&					registry = Registry::get();
	std::lock_guard<std::mutex> lock(registry.mutex);
	registry.channels.erase(std::remove(registry.channels.begin(), registry.channels.end(), this), registry.channels.end());
	registry.received += received_.load();
	registry.sent += sent_.load();
	registry.recv_errors += recv_errors_.load();
	registry.send_errors += send_errors_.load();
}

void ChannelStats::received(int64_t timestamp)
{
	++received_;
	static const int64_t frequency = [] {
		LARGE_INTEGER value = {};
		return QueryPerformanceFrequency(&value) && value.QuadPart > 0 ? static_cast<int64_t>(value.QuadPart) : int64_t{0};
	}();
	LARGE_INTEGER now = {};
	if (frequency == 0 || timestamp <= 0 || !QueryPerformanceCounter(&now) || now.QuadPart <= timestamp)
		return;
	const int64_t lag_us = (now.QuadPart - timestamp) * 1000000 / frequency;
	int64_t		  seen	 = max_lag_us_.load(std::memory_order_relaxed);
	while (lag_us > seen && !max_lag_us_.compare_exchange_weak(seen, lag_us, std::memory_order_relaxed))
	{
	}
}

void ChannelStats::sent()
{
	++sent_;
}

void ChannelStats::recv_failed()
{
	++recv_errors_;
}

void ChannelStats::send_failed()
{
	++send_errors_;
}

void ChannelStats::set_queued(uint64_t queued)
{
	queued_.store(queued, std::memory_order_relaxed);
}

namespace {
	/// A packet that waited this long in the driver's queue is at risk: the driver drops packets older than its queue time.
	constexpr int64_t kLagWarnMs = 250;

	enum class Driver
	{
		running,
		not_running,
		missing,
		unknown,
	};

	/// The WinDivert driver service is created when the first handle is opened. If it stops or is deleted while handles are
	/// open, capture has silently ended.
	Driver driver_state()
	{
		SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
		if (manager == nullptr)
			return Driver::unknown;
		Driver		  state	  = Driver::unknown;
		SC_HANDLE	  service = OpenServiceW(manager, L"WinDivert", SERVICE_QUERY_STATUS);
		if (service == nullptr)
			state = GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST ? Driver::missing : Driver::unknown;
		else
		{
			SERVICE_STATUS status = {};
			if (QueryServiceStatus(service, &status))
				state = status.dwCurrentState == SERVICE_RUNNING ? Driver::running : Driver::not_running;
			CloseServiceHandle(service);
		}
		CloseServiceHandle(manager);
		return state;
	}

	Totals								  previous;
	std::string							  cached;
	std::chrono::steady_clock::time_point last_sample;
	bool								  sampled			= false;
	bool								  previous_backlog	= false;
	bool								  previous_lagging	= false;
	Driver								  previous_driver	= Driver::running;

	std::string sample(uint32_t backlog_threshold)
	{
		const Totals totals	 = Registry::get().collect();
		const Driver driver	 = driver_state();
		const bool	 healthy = driver == Driver::running || driver == Driver::unknown;

		const bool receive_errors = totals.recv_errors > previous.recv_errors;
		const bool send_errors	  = totals.send_errors > previous.send_errors;
		const bool backlog		  = totals.queued >= backlog_threshold;
		const bool lagging		  = totals.max_lag_us / 1000 >= kLagWarnMs;
		if (receive_errors)
			LOG_WARN("WinDivert failed to receive %llu time(s)", static_cast<unsigned long long>(totals.recv_errors - previous.recv_errors));
		if (send_errors)
			LOG_WARN("WinDivert failed to send %llu time(s)", static_cast<unsigned long long>(totals.send_errors - previous.send_errors));
		// Backlog and lag are reported when they start and when they clear, not on every sample
		if (backlog && !previous_backlog)
			LOG_WARN("%llu packets are waiting for the engine (threshold %u)", static_cast<unsigned long long>(totals.queued), backlog_threshold);
		else if (!backlog && previous_backlog)
			LOG_INFO("the receive backlog cleared (%llu waiting)", static_cast<unsigned long long>(totals.queued));
		if (lagging && !previous_lagging)
			LOG_WARN("packets wait %lld ms in the WinDivert driver queue, which drops packets that wait too long",
					 static_cast<long long>(totals.max_lag_us / 1000));
		else if (!lagging && previous_lagging)
			LOG_INFO("the WinDivert driver queue delay is back to %lld ms", static_cast<long long>(totals.max_lag_us / 1000));
		if (driver != previous_driver)
		{
			const bool was_healthy = previous_driver == Driver::running || previous_driver == Driver::unknown;
			if (healthy && !was_healthy)
				LOG_INFO("the WinDivert driver is running again");
			else if (driver == Driver::missing)
				LOG_ERROR("the WinDivert driver service is gone; capture has ended");
			else if (driver == Driver::not_running)
				LOG_ERROR("the WinDivert driver is no longer running; capture has ended");
			previous_driver = driver;
		}
		previous_backlog = backlog;
		previous_lagging = lagging;
		previous		 = totals;

		std::string line = "windivert: " + std::to_string(totals.handles) + " handle(s) recv " + std::to_string(totals.received) + " sent " +
						   std::to_string(totals.sent) + " errors " + std::to_string(totals.recv_errors) + "/" +
						   std::to_string(totals.send_errors) + " waiting " + std::to_string(totals.queued) + " lag " +
						   std::to_string(totals.max_lag_us / 1000) + "ms";
		switch (driver)
		{
			case Driver::running:
				line += " | driver ok";
				break;
			case Driver::unknown:
				line += " | driver state unknown";
				break;
			case Driver::missing:
				line += " | DRIVER MISSING (capture has ended!)";
				break;
			case Driver::not_running:
				line += " | DRIVER STOPPED (capture has ended!)";
				break;
		}
		return receive_errors || send_errors || backlog || lagging || !healthy ? line + " [!]" : line;
	}
}  // namespace

std::string monitor_status(uint64_t interval_ms, uint32_t backlog_threshold)
{
	const auto now = std::chrono::steady_clock::now();
	if (!sampled || now - last_sample >= std::chrono::milliseconds(interval_ms))
	{
		cached		= sample(backlog_threshold);
		last_sample = now;
		sampled		= true;
	}
	return cached;
}

}  // namespace wd

#endif
