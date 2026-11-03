#ifndef WINDIVERT_MONITOR_H_
#define WINDIVERT_MONITOR_H_

#include <atomic>
#include <cstdint>
#include <string>

namespace wd {

#ifdef LAGSW_FEATURE_BACKEND_MONITOR
/// Counters of one WinDivert handle (or of the receive queue that merges two of them). Registers itself for monitor_status()
/// while it exists; the counts of a destroyed instance stay in the totals. All methods are thread-safe.
class ChannelStats
{
public:
	/// `is_handle` is false for an object that only reports a queue depth and is not a WinDivert handle itself.
	explicit ChannelStats(bool is_handle = true);
	~ChannelStats();

	ChannelStats(const ChannelStats&)			 = delete;
	ChannelStats& operator=(const ChannelStats&) = delete;

	/// A packet was received. `timestamp` is the WinDivert interception time (QueryPerformanceCounter ticks); the age it has
	/// on arrival is how long the packet sat in the driver's queue.
	void received(int64_t timestamp);
	void sent();
	void recv_failed();
	void send_failed();
	/// The number of packets waiting in user space for the engine to take them.
	void set_queued(uint64_t queued);

private:
	friend struct Registry;
	const bool			  is_handle_;
	std::atomic<uint64_t> received_{0};
	std::atomic<uint64_t> sent_{0};
	std::atomic<uint64_t> recv_errors_{0};
	std::atomic<uint64_t> send_errors_{0};
	std::atomic<uint64_t> queued_{0};
	std::atomic<int64_t>  max_lag_us_{0};
};

/// Summarizes the WinDivert handles opened by this process and checks that the WinDivert driver is still running, then returns
/// a one-line summary. The sample is reused until `interval_ms` has elapsed, so the service query stays cheap when called
/// often. `backlog_threshold` is the number of packets waiting in user space at which the summary is flagged. Not thread-safe.
std::string monitor_status(uint64_t interval_ms, uint32_t backlog_threshold);
#else
class ChannelStats
{
public:
	explicit ChannelStats(bool = true) {}
	void received(int64_t) {}
	void sent() {}
	void recv_failed() {}
	void send_failed() {}
	void set_queued(uint64_t) {}
};
#endif

}  // namespace wd

#endif
