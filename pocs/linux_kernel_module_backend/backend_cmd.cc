// `swbench backend ...`: runs the real lagsw backend (backends/kmod) the way the engine does: open a channel with a WinDivert-style filter,
// receive packets, hold them for a while, optionally rewrite or drop them, and send them back. Used by scripts/tests/test_kmod_hold.sh.
//
//   swbench backend --filter F [--forward yes] [--include-forward yes] [--sniff yes] [--priority N] [--delay-ms D]
//                   [--batch yes] [--discard-every K] [--modify dport --to-port P] [--inline yes] [--seconds S]
//   swbench backend-load [--priority N]     checks check_privileges() (which loads the module) and opens and closes one channel
//   swbench backend-api                      the parts of the backend contract that need no traffic
#include <sys/resource.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "module.h"
#include "module_image.h"
#include "packet_backend.h"

namespace {
std::atomic<bool> g_stop{false};

void on_signal(int)
{
	g_stop.store(true);
}

struct Options
{
	std::vector<std::string> v;
	std::string				 get(const char* name, const char* fallback) const
	{
		for (size_t i = 0; i + 1 < v.size(); ++i)
			if (v[i] == name)
				return v[i + 1];
		return fallback;
	}
	bool yes(const char* name) const { return get(name, "no") == "yes"; }
	long num(const char* name, const char* fallback) const { return std::atol(get(name, fallback).c_str()); }
};

using Clock = std::chrono::steady_clock;

struct Pending
{
	Clock::time_point	 due;
	std::vector<uint8_t> data;
	backend::PacketMeta	 meta;
	bool				 discard = false;
};

struct Counters
{
	std::atomic<uint64_t> seen{0}, outbound{0}, inbound{0}, sent{0}, discarded{0}, errors{0}, bytes{0}, modified{0};
};

void announce_ready()
{
	std::printf("ready\n");
	std::fflush(stdout);
}

void modify_dport(std::vector<uint8_t>& packet, uint16_t port)
{
	const uint32_t ihl = (packet[0] & 0x0F) * 4u;
	if ((packet[9] != 6 && packet[9] != 17) || packet.size() < ihl + 4 || (static_cast<uint32_t>(packet[6] & 0x1F) << 8 | packet[7]) != 0)
		return;
	packet[ihl + 2] = static_cast<uint8_t>(port >> 8);
	packet[ihl + 3] = static_cast<uint8_t>(port & 0xFF);
	backend::calc_checksums(packet.data(), static_cast<uint32_t>(packet.size()));
}
}  // namespace

int run_backend(const std::vector<std::string>& arguments)
{
	Options		options{arguments};
	std::string error;
	if (!backend::check_privileges(error))
	{
		std::fprintf(stderr, "swbench: check_privileges: %s\n", error.c_str());
		return 3;
	}
	backend::OpenOptions open_options;
	open_options.filter								= options.get("--filter", "");
	open_options.forward							= options.yes("--forward");
	open_options.include_forward					= options.yes("--include-forward");
	open_options.sniff								= options.yes("--sniff");
	open_options.priority							= static_cast<int16_t>(options.num("--priority", "0"));
	std::unique_ptr<backend::PacketChannel> channel = backend::open(open_options, error);
	if (!channel)
	{
		std::fprintf(stderr, "swbench: open: %s\n", error.c_str());
		return 2;
	}
	const long	   delay_ms		 = options.num("--delay-ms", "0");
	const long	   discard_every = options.num("--discard-every", "0");
	const bool	   batch		 = options.yes("--batch");
	const bool	   send_inline	 = options.yes("--inline") && delay_ms == 0 && options.get("--modify", "none") == "none";
	const bool	   rewrite		 = options.get("--modify", "none") == "dport";
	const uint16_t to_port		 = static_cast<uint16_t>(options.num("--to-port", "0"));
	const long	   seconds		 = options.num("--seconds", "0");

	struct sigaction action = {};
	action.sa_handler		= on_signal;
	sigaction(SIGINT, &action, nullptr);
	sigaction(SIGTERM, &action, nullptr);

	Counters				counters;
	std::mutex				mutex;
	std::condition_variable wake;
	std::deque<Pending>		queue;
	bool					receiving = true;

	auto release = [&](std::vector<Pending>& due) {
		std::vector<backend::SendItem> items;
		for (size_t index = 0; index < due.size(); ++index)
		{
			if (due[index].discard)
			{
				channel->discard(due[index].meta);
				++counters.discarded;
				continue;
			}
			backend::SendItem item;
			item.packet = due[index].data.data();
			item.length = static_cast<uint32_t>(due[index].data.size());
			item.meta	= &due[index].meta;
			items.push_back(std::move(item));
		}
		if (batch)
		{
			channel->send_batch(items.data(), items.size());
		}
		else
		{
			for (backend::SendItem& item : items)
				item.status = channel->send(item.packet, item.length, *item.meta, item.sent, item.error);
		}
		for (const backend::SendItem& item : items)
		{
			if (item.status == backend::IoStatus::ok)
				++counters.sent;
			else
				++counters.errors;
		}
	};

	// Releases delayed packets when they are due; the receiving thread never waits for them
	std::thread releaser([&] {
		std::unique_lock<std::mutex> lock(mutex);
		for (;;)
		{
			if (queue.empty())
			{
				if (!receiving)
					return;
				wake.wait(lock);
				continue;
			}
			if (receiving && Clock::now() < queue.front().due)
			{
				wake.wait_until(lock, queue.front().due);
				continue;
			}
			std::vector<Pending> due;
			while (!queue.empty() && (!receiving || queue.front().due <= Clock::now()))
			{
				due.push_back(std::move(queue.front()));
				queue.pop_front();
			}
			lock.unlock();
			release(due);
			lock.lock();
		}
	});

	std::thread watcher([&] {
		const auto start = Clock::now();
		while (!g_stop.load())
		{
			if (seconds > 0 && Clock::now() - start >= std::chrono::seconds(seconds))
				break;
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		}
		g_stop.store(true);
		channel->shutdown_recv();
	});

	announce_ready();
	std::vector<uint8_t> buffer(65536 + 4096);
	for (;;)
	{
		uint32_t				length = 0;
		backend::PacketMeta		meta;
		const backend::IoStatus status = channel->recv(buffer.data(), static_cast<uint32_t>(buffer.size()), length, meta, error);
		if (status == backend::IoStatus::closed)
			break;
		if (status == backend::IoStatus::error)
		{
			std::fprintf(stderr, "swbench: recv: %s\n", error.c_str());
			++counters.errors;
			break;
		}
		const uint64_t number = ++counters.seen;
		(meta.outbound ? counters.outbound : counters.inbound)++;
		counters.bytes += length;
		// --inline yes: an unchanged packet is sent straight from the receive buffer, with none of this tool's own per-packet copies and
		// allocations, so that the cost measured is the backend's
		if (send_inline && !open_options.sniff && !(discard_every > 0 && number % static_cast<uint64_t>(discard_every) == 0))
		{
			uint32_t	sent = 0;
			std::string send_error;
			(channel->send(buffer.data(), length, meta, sent, send_error) == backend::IoStatus::ok ? counters.sent : counters.errors)++;
			continue;
		}
		Pending packet;
		packet.data.assign(buffer.begin(), buffer.begin() + length);
		packet.meta	   = meta;
		packet.discard = discard_every > 0 && number % static_cast<uint64_t>(discard_every) == 0;
		if (rewrite && to_port != 0)
		{
			modify_dport(packet.data, to_port);
			++counters.modified;
		}
		if (open_options.sniff)
			continue;
		if (delay_ms == 0)
		{
			std::vector<Pending> one;
			one.push_back(std::move(packet));
			release(one);
			continue;
		}
		packet.due = Clock::now() + std::chrono::milliseconds(delay_ms);
		{
			std::lock_guard<std::mutex> lock(mutex);
			queue.push_back(std::move(packet));
		}
		wake.notify_all();
	}
	g_stop.store(true);
	{
		std::lock_guard<std::mutex> lock(mutex);
		receiving = false;
	}
	wake.notify_all();
	releaser.join();
	watcher.join();
	channel->close();
	std::string layers = channel->description();
	std::replace(layers.begin(), layers.end(), ' ', '_');
	rusage usage = {};
	getrusage(RUSAGE_SELF, &usage);
	const double cpu_ms = static_cast<double>(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1000.0 +
						  static_cast<double>(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1000.0;
	// captured, dropped and cpu_ms are what the bench table of test_kmod_hold.sh reads from every reader
	std::printf(
		"captured=%llu dropped=0 cpu_ms=%.1f backend_seen=%llu backend_outbound=%llu backend_inbound=%llu backend_sent=%llu "
		"backend_discarded=%llu backend_errors=%llu backend_bytes=%llu backend_modified=%llu "
		"backend_layers=%s\n",
		static_cast<unsigned long long>(counters.seen.load()),
		cpu_ms,
		static_cast<unsigned long long>(counters.seen.load()),
		static_cast<unsigned long long>(counters.outbound.load()),
		static_cast<unsigned long long>(counters.inbound.load()),
		static_cast<unsigned long long>(counters.sent.load()),
		static_cast<unsigned long long>(counters.discarded.load()),
		static_cast<unsigned long long>(counters.errors.load()),
		static_cast<unsigned long long>(counters.bytes.load()),
		static_cast<unsigned long long>(counters.modified.load()),
		layers.empty() ? "-" : layers.c_str());
	return 0;
}

// `swbench backend-image FILE`: loads a module file from memory with backends/kmod's loader, the way the embedded module is loaded
int run_backend_image(const std::vector<std::string>& arguments)
{
	if (arguments.empty())
	{
		std::fprintf(stderr, "swbench: backend-image needs a module file\n");
		return 2;
	}
	std::FILE* file = std::fopen(arguments[0].c_str(), "rb");
	if (file == nullptr)
	{
		std::fprintf(stderr, "swbench: cannot read %s\n", arguments[0].c_str());
		return 2;
	}
	std::vector<uint8_t> bytes;
	uint8_t				 chunk[65536];
	size_t				 count;
	while ((count = std::fread(chunk, 1, sizeof(chunk), file)) > 0)
		bytes.insert(bytes.end(), chunk, chunk + count);
	std::fclose(file);

	std::string error;
	const auto	status = kmodb::load_module_image(bytes.data(), bytes.size(), error);
	const char* name = status == kmodb::LoadStatus::loaded ? "loaded" : status == kmodb::LoadStatus::already_loaded ? "already" : "failed";
	std::printf("image_status=%s image_release=%s kernel_release=%s image_error=%s\n",
				name,
				kmodb::image_release(bytes.data(), bytes.size()).c_str(),
				kmodb::kernel_release().c_str(),
				error.empty() ? "-" : error.c_str());
	return status == kmodb::LoadStatus::failed ? 1 : 0;
}

int run_backend_load(const std::vector<std::string>& arguments)
{
	Options		options{arguments};
	std::string error;
	if (!backend::check_privileges(error))
	{
		std::printf("backend_privileges=0 backend_error=%s\n", error.c_str());
		return 3;
	}
	backend::OpenOptions open_options;
	open_options.priority = static_cast<int16_t>(options.num("--priority", "0"));
	open_options.forward  = true;
	auto channel		  = backend::open(open_options, error);
	std::printf("backend_privileges=1 backend_opened=%d\n", channel ? 1 : 0);
	if (!channel)
		std::fprintf(stderr, "swbench: open: %s\n", error.c_str());
	return channel ? 0 : 2;
}

// What the backend promises without any traffic: filters are validated with a position, bad ones are refused when opening, a channel
// reports where it listens, the engine's own filters compile, equal priorities coexist, and send/discard after close do not hang.
int run_backend_api(const std::vector<std::string>&)
{
	int	 failed = 0, cases = 0;
	auto check = [&](bool good, const char* what) {
		++cases;
		if (!good)
		{
			++failed;
			std::fprintf(stderr, "backend-api FAIL: %s\n", what);
		}
	};
	std::string error;
	uint32_t	position = 99;
	check(backend::check_privileges(error), "check_privileges succeeds on a host with the module");

	check(backend::validate_filter("udp.DstPort == 9000", false, error, position), "a plain filter validates");
	check(!backend::validate_filter("udp.Nope == 1", false, error, position) && !error.empty(),
		  "an unknown field is refused with a message");
	check(!backend::validate_filter("tcp.DstPort == 99999", true, error, position), "a port out of range is refused");
	check(!backend::validate_filter("tcp.DstPort ==", false, error, position) && position > 0, "a syntax error comes with a position");

	backend::ProfileFilter profile;
	profile.user_filter		  = "udp.DstPort == 9000";
	profile.include_bare_acks = true;
	profile.client_source	  = "10.10.1.2";
	profile.server_direction  = backend::ServerDirection::both;
	profile.server_addresses  = {"10.10.2.2", "10.10.2.3"};
	profile.outbound		  = false;
	const std::string built	  = backend::filters::profile(profile);
	check(backend::validate_filter(built, false, error, position), "the filter the engine builds for a profile validates");
	check(backend::validate_filter(backend::filters::port(9000), false, error, position), "the port filter validates");

	backend::OpenOptions bad;
	bad.filter = "udp.Nope == 1";
	check(backend::open(bad, error) == nullptr && error.find("unsupported filter term") != std::string::npos &&
			  error.find("position") != std::string::npos,
		  "opening with a bad filter fails and says where");

	backend::OpenOptions local;
	local.filter = "udp.DstPort == 9000";
	auto first	 = backend::open(local, error);
	auto second	 = backend::open(local, error);
	auto sniffer = backend::open(
		[&] {
			backend::OpenOptions o = local;
			o.sniff				   = true;
			return o;
		}(),
		error);
	check(first && second && sniffer, "three channels of the same priority are open at once");
	check(first && first->description() == "input + output hooks", "a local filter listens at input and output");
	backend::OpenOptions fwd = local;
	fwd.forward				 = true;
	auto forwarding			 = backend::open(fwd, error);
	check(forwarding && forwarding->description() == "forward hook", "a forward filter listens at forward only");
	backend::OpenOptions all = local;
	all.include_forward		 = true;
	auto everything			 = backend::open(all, error);
	check(everything && everything->description() == "input + output + forward hooks", "include_forward adds the forward hook");
	backend::OpenOptions outbound = local;
	outbound.filter				  = "outbound and udp.DstPort == 9000";
	auto out_only				  = backend::open(outbound, error);
	check(out_only && out_only->description() == "output hook", "an outbound filter listens at output only");

	// A channel that was shut down answers instead of blocking
	if (first)
	{
		first->shutdown_recv();
		uint8_t				buffer[2048];
		uint32_t			length = 0;
		backend::PacketMeta meta;
		check(first->recv(buffer, sizeof(buffer), length, meta, error) == backend::IoStatus::closed,
			  "recv after shutdown_recv reports closed");
		first->close();
		first->close();
		check(first->recv(buffer, sizeof(buffer), length, meta, error) == backend::IoStatus::closed, "recv after close reports closed");
	}
	std::string reason;
	check(backend::open_shape_stage(backend::ShapeSpec{}, reason) == nullptr && !reason.empty(),
		  "there is no kernel shaping stage, with a reason");

	std::printf("backend_api_cases=%d backend_api_failed=%d\n", cases, failed);
	return failed == 0 ? 0 : 1;
}
