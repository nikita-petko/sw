#ifndef LAGSW_DISCONNECT_DETECTOR_H
#define LAGSW_DISCONNECT_DETECTOR_H

#include <cstddef>
#include <cstdint>
#include <deque>

/// Detects a disconnect from the packet counts of consecutive server-discovery windows. A window whose count falls
/// below a fraction of the recent average marks the connection as lost until the count recovers.
class DisconnectDetector
{
public:
	enum class Event
	{
		none,
		disconnected,
		reconnected
	};

	/// A disconnect needs a trailing average of at least this many packets per window, so idle links never trigger it.
	static constexpr double kMinAveragePackets = 10.0;
	/// Windows required before the average is trusted.
	static constexpr size_t kMinHistory = 3;
	/// Windows averaged.
	static constexpr size_t kMaxHistory = 6;

	/// `drop_percent` is how far a window must fall below the average to count as a disconnect. 0 disables detection.
	explicit DisconnectDetector(uint32_t drop_percent) : drop_percent_(drop_percent > 100 ? 100 : drop_percent) {}

	/// Feeds the packet count of a finished window.
	Event observe(uint64_t packets)
	{
		if (drop_percent_ == 0)
			return Event::none;
		const double avg	   = average();
		const double threshold = avg * static_cast<double>(100 - drop_percent_) / 100.0;
		const bool	 baseline  = history_.size() >= kMinHistory && avg >= kMinAveragePackets;
		const bool	 dropped   = baseline && static_cast<double>(packets) < threshold;

		if (disconnected_)
		{
			if (dropped)
				return Event::none;
			disconnected_ = false;
			history_.clear();
			history_.push_back(packets);
			return Event::reconnected;
		}
		if (dropped)
		{
			disconnected_ = true;
			return Event::disconnected;
		}
		history_.push_back(packets);
		if (history_.size() > kMaxHistory)
			history_.pop_front();
		return Event::none;
	}

	/// Forgets the history, e.g. when windows were skipped and the counts are no longer comparable.
	void reset()
	{
		history_.clear();
		disconnected_ = false;
	}

	/// Trailing average of the healthy windows seen so far, or the average before the drop while disconnected.
	double average() const
	{
		if (history_.empty())
			return 0.0;
		uint64_t total = 0;
		for (const uint64_t count : history_)
			total += count;
		return static_cast<double>(total) / static_cast<double>(history_.size());
	}

	bool disconnected() const { return disconnected_; }

private:
	uint32_t			  drop_percent_;
	std::deque<uint64_t>  history_;
	bool				  disconnected_ = false;
};

#endif
