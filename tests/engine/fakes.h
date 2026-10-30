// Fake capture backend and platform services for the engine tests. The engine talks to the outside world only through the
// backend:: and platform:: free functions, so linking these definitions instead of the real ones lets the whole engine, with its
// worker threads, run against in-memory channels. The clock stays real; tests wait for conditions instead of sleeping.
#ifndef TESTS_ENGINE_FAKES_H_
#define TESTS_ENGINE_FAKES_H_

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "packet_backend.h"
#include "platform.h"

namespace fakes {

struct SentPacket
{
	std::vector<uint8_t> data;
	backend::PacketMeta	 meta;
};

/// The test-visible half of an open channel. The engine owns the other half (a FakeChannel) and the two share this state.
class ChannelState
{
public:
	/// Queues a packet for the engine's next recv(). `id` is stored in the metadata timestamp so packets can be told apart.
	void inject(const std::vector<uint8_t>& packet, int64_t id = 0, bool outbound = false, uint32_t if_index = 0);
	/// Makes subsequent send() calls fail.
	void fail_sends(bool fail);

	size_t				   sent_count() const;
	std::vector<SentPacket> sent_packets() const;
	/// Timestamps (ids) of the packets the engine discarded.
	std::vector<int64_t>   discarded() const;
	/// Number of injected packets the engine has taken so far.
	size_t				   consumed() const;
	bool				   closed() const;
	bool				   recv_shut_down() const;

	backend::OpenOptions options;
	std::string			 filter;

private:
	friend class FakeChannel;
	struct Inbound
	{
		std::vector<uint8_t> data;
		backend::PacketMeta	 meta;
	};
	mutable std::mutex		m_;
	std::condition_variable cv_;
	std::deque<Inbound>		inbound_;
	std::vector<SentPacket> sent_;
	std::vector<int64_t>	discarded_;
	size_t					consumed_		  = 0;
	bool					recv_shutdown_	  = false;
	bool					closed_			  = false;
	bool					fail_sends_		  = false;
};

/// Forgets every channel and recorded call; run at the start of each test.
void reset();

/// Channels in the order the engine opened them.
std::vector<std::shared_ptr<ChannelState>> channels();
std::shared_ptr<ChannelState>			   channel(size_t index);
/// The most recently opened channel whose filter equals `filter`, or null.
std::shared_ptr<ChannelState>			   channel_with_filter(const std::string& filter);
/// Makes the next backend::open() fail with `message`.
void									   fail_next_open(const std::string& message);

/// Profile filter specifications in the order filters::profile() was called; a profile channel's filter is "profile#<index>".
std::vector<backend::ProfileFilter> profile_specs();
backend::ProfileFilter			   last_profile_spec();

/// Counts of begin_timer_resolution() / end_timer_resolution() calls.
int timer_resolution_begins();
int timer_resolution_ends();

/// Answers platform::https_get(); without a handler every request fails with status 0.
void set_http_handler(std::function<platform::HttpResponse(const std::string& host, const std::string& path)> handler);
/// Paths requested over https so far.
std::vector<std::string> http_requests();

/// Polls `condition` until it holds or the timeout expires; returns whether it held.
inline bool wait_until(const std::function<bool()>& condition, std::chrono::milliseconds timeout = std::chrono::milliseconds(5000))
{
	const auto deadline = std::chrono::steady_clock::now() + timeout;
	while (!condition())
	{
		if (std::chrono::steady_clock::now() > deadline)
			return false;
		std::this_thread::sleep_for(std::chrono::milliseconds(2));
	}
	return true;
}

}  // namespace fakes

#endif
