// WinDivert counterpart of pocs/linux_kernel_module_backend/swbench.cc: a paced UDP sender, a latency-recording sink and a
// divert-and-resume "hold" reader that gives every captured packet a verdict D ms after it was captured, as the engine does.
// Run the same traffic with and without the hold reader to tell the cost of the driver and of the user-space interface apart.
// Results are printed as one `key=value` line per role, parsed by bench.ps1.
//   wdbench flood --dst IP --port P --pps N --seconds S [--size B] [--stream 0-7]
//   wdbench sink  --port P [--seconds S]
//   wdbench hold  --port P [--layer network|forward] [--filter F] [--delay-ms D] [--drop-every K] [--batch N]
//                 [--priority N] [--queue-length N] [--queue-time-ms N] [--seconds S]
// Timestamps are QueryPerformanceCounter (one clock per machine), so one-way latency needs the sender, the hold reader and the
// sink on ONE machine (loopback or a local interface address). For a real client -> host -> VPN path run only `hold` on the host
// (--layer forward) and compare loss, reordering and the cap_/over_/send_ numbers with and without it.
// The latency in the payload is split in parts, which is what separates a driver problem from an interface one:
//   cap_*   sender stamp -> WinDivertRecv returned      (driver: stack -> filter -> queue -> wake-up)
//   over_*  verdict due time -> WinDivertSend called    (interface: our scheduling and queueing of the hold)
//   send_*  duration of the WinDivertSend call          (driver: re-injection)
//   lat_*   sender stamp -> sink received               (everything; compare with the same run without `hold`)
// reordered counts packets of a stream that arrive after a later one: swapped or late weapon packets show up there.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mmsystem.h>

#include <windivert.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {
std::atomic<bool> g_stop{false};

std::atomic<HANDLE> g_divert{INVALID_HANDLE_VALUE};

// A blocked WinDivertRecvEx never looks at g_stop; shutting the handle down makes it return
void request_stop()
{
	g_stop				= true;
	const HANDLE divert = g_divert.load();
	if (divert != INVALID_HANDLE_VALUE)
		WinDivertShutdown(divert, WINDIVERT_SHUTDOWN_RECV);
}

BOOL WINAPI on_signal(DWORD)
{
	request_stop();
	return TRUE;
}

[[noreturn]] void die(const char* what, DWORD code = GetLastError())
{
	std::fprintf(stderr, "wdbench: %s failed (error %lu)\n", what, static_cast<unsigned long>(code));
	std::exit(1);
}

struct Args
{
	std::vector<std::string> v;
	std::string				 get(const char* name, const char* fallback = nullptr) const
	{
		for (size_t i = 0; i + 1 < v.size(); ++i)
			if (v[i] == name)
				return v[i + 1];
		if (!fallback)
		{
			std::fprintf(stderr, "wdbench: missing %s\n", name);
			std::exit(2);
		}
		return fallback;
	}
	long num(const char* name, const char* fallback = nullptr) const { return std::atol(get(name, fallback).c_str()); }
};

uint64_t now_ns()
{
	static const LONGLONG freq = [] {
		LARGE_INTEGER f;
		QueryPerformanceFrequency(&f);
		return f.QuadPart;
	}();
	LARGE_INTEGER t;
	QueryPerformanceCounter(&t);
	return static_cast<uint64_t>(t.QuadPart / freq) * 1000000000ull + static_cast<uint64_t>(t.QuadPart % freq) * 1000000000ull / static_cast<uint64_t>(freq);
}

double cpu_ms_self()
{
	FILETIME creation, exit_time, kernel, user;
	GetProcessTimes(GetCurrentProcess(), &creation, &exit_time, &kernel, &user);
	auto to_ms = [](FILETIME f) { return static_cast<double>((static_cast<uint64_t>(f.dwHighDateTime) << 32) | f.dwLowDateTime) / 10000.0; };
	return to_ms(kernel) + to_ms(user);
}

void announce_ready()
{
	std::printf("ready\n");
	std::fflush(stdout);
}

// Microsecond samples with percentiles
struct Samples
{
	std::vector<uint32_t> us;
	void add(uint64_t from_ns, uint64_t to_ns)
	{
		us.push_back(static_cast<uint32_t>(std::min<uint64_t>(to_ns > from_ns ? (to_ns - from_ns) / 1000 : 0, 0xFFFFFFFFull)));
	}
	void print(const char* prefix)
	{
		std::sort(us.begin(), us.end());
		auto pct = [&](double p) { return us.empty() ? 0u : us[static_cast<size_t>(p * static_cast<double>(us.size() - 1))]; };
		std::printf(" %s_p50_us=%u %s_p99_us=%u %s_p999_us=%u %s_max_us=%u", prefix, pct(0.50), prefix, pct(0.99), prefix, pct(0.999), prefix, us.empty() ? 0u : us.back());
	}
};

void stop_after(long seconds)
{
	if (seconds > 0)
		std::thread([seconds] {
			for (long i = 0; i < seconds * 10 && !g_stop; ++i)
				Sleep(100);
			request_stop();
		}).detach();
}

struct Winsock
{
	Winsock()
	{
		WSADATA data;
		if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
			die("WSAStartup");
	}
};

// Bytes 0-7: send time (now_ns), 8-15: sequence number (stream in the high 32 bits), rest: 'x'
int run_flood(const Args& args)
{
	Winsock			  winsock;
	const std::string dst	  = args.get("--dst");
	const long		  port	  = args.num("--port");
	const long		  pps	  = args.num("--pps");
	const long		  seconds = args.num("--seconds");
	const long		  size	  = args.num("--size", "512");
	const uint64_t	  stream  = static_cast<uint64_t>(args.num("--stream", "0")) & 7;
	if (size < 16 || pps <= 0)
	{
		std::fprintf(stderr, "wdbench: --size must be at least 16 and --pps positive\n");
		return 2;
	}

	SOCKET fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == INVALID_SOCKET)
		die("socket", static_cast<DWORD>(WSAGetLastError()));
	int sndbuf = 8 << 20;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&sndbuf), sizeof(sndbuf));
	sockaddr_in to = {};
	to.sin_family  = AF_INET;
	to.sin_port	   = htons(static_cast<uint16_t>(port));
	inet_pton(AF_INET, dst.c_str(), &to.sin_addr);
	if (connect(fd, reinterpret_cast<sockaddr*>(&to), sizeof(to)) != 0)
		die("connect", static_cast<DWORD>(WSAGetLastError()));

	timeBeginPeriod(1);
	std::vector<char> payload(static_cast<size_t>(size), 'x');
	const uint64_t	  start	   = now_ns();
	const uint64_t	  end	   = start + static_cast<uint64_t>(seconds) * 1000000000ull;
	const double	  interval = 1e9 / static_cast<double>(pps);
	uint64_t		  sent = 0, failed = 0;
	for (;;)
	{
		const uint64_t now = now_ns();
		if (now >= end)
			break;
		// Everything that should have been sent by now goes out in one burst; this keeps the average rate exact
		const uint64_t due = static_cast<uint64_t>(static_cast<double>(now - start) / interval) + 1;
		if (sent + failed >= due)
		{
			Sleep(0);
			continue;
		}
		while (sent + failed < due)
		{
			const uint64_t stamp = now_ns();
			const uint64_t seq	 = (stream << 32) | (sent + failed);
			std::memcpy(payload.data(), &stamp, sizeof(stamp));
			std::memcpy(payload.data() + 8, &seq, sizeof(seq));
			if (send(fd, payload.data(), static_cast<int>(payload.size()), 0) < 0)
				++failed;
			else
				++sent;
		}
	}
	timeEndPeriod(1);
	std::printf("sent=%llu failed=%llu cpu_ms=%.1f\n", static_cast<unsigned long long>(sent), static_cast<unsigned long long>(failed), cpu_ms_self());
	return 0;
}

int run_sink(const Args& args)
{
	Winsock	   winsock;
	const long port = args.num("--port");
	SOCKET	   fd	= socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd == INVALID_SOCKET)
		die("socket", static_cast<DWORD>(WSAGetLastError()));
	int rcvbuf = 32 << 20;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));
	DWORD timeout_ms = 100;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
	sockaddr_in addr = {};
	addr.sin_family	 = AF_INET;
	addr.sin_port	 = htons(static_cast<uint16_t>(port));
	if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
		die("bind", static_cast<DWORD>(WSAGetLastError()));
	SetConsoleCtrlHandler(on_signal, TRUE);
	stop_after(args.num("--seconds", "0"));
	timeBeginPeriod(1);
	announce_ready();

	char				 buffer[2048];
	uint64_t			 received = 0, corrupt = 0, dups = 0, reordered = 0;
	uint64_t			 max_seq[8] = {};
	std::vector<uint8_t> seen[8];
	Samples				 latency;
	latency.us.reserve(1 << 20);
	while (!g_stop)
	{
		const int len = recv(fd, buffer, sizeof(buffer), 0);
		if (len < 0)
			continue;
		const uint64_t now = now_ns();
		++received;
		if (len < 16)
		{
			++corrupt;
			continue;
		}
		uint64_t stamp, seq;
		std::memcpy(&stamp, buffer, sizeof(stamp));
		std::memcpy(&seq, buffer + 8, sizeof(seq));
		latency.add(stamp, now);
		const unsigned stream = static_cast<unsigned>(seq >> 32) & 7;
		const uint64_t n	  = seq & 0xFFFFFFFFull;
		if (n < (1ull << 26))
		{
			if (n >= seen[stream].size())
				seen[stream].resize(static_cast<size_t>(n) + 1024, 0);
			if (seen[stream][static_cast<size_t>(n)]++)
				++dups;
		}
		if (n < max_seq[stream])
			++reordered;
		max_seq[stream] = std::max(max_seq[stream], n);
	}
	timeEndPeriod(1);
	std::printf("received=%llu cpu_ms=%.1f corrupt=%llu dups=%llu reordered=%llu",
				static_cast<unsigned long long>(received),
				cpu_ms_self(),
				static_cast<unsigned long long>(corrupt),
				static_cast<unsigned long long>(dups),
				static_cast<unsigned long long>(reordered));
	latency.print("lat");
	std::printf("\n");
	return 0;
}

struct Held
{
	std::vector<uint8_t> data;
	WINDIVERT_ADDRESS	 address;
	uint64_t			 due_ns;
};

struct HoldStats
{
	uint64_t captured = 0, sent = 0, dropped = 0, send_failed = 0;
	Samples	 cap, over, send;
};

void send_one(HANDLE handle, const Held& held, HoldStats& stats)
{
	UINT		   written = 0;
	const uint64_t before  = now_ns();
	const bool	   ok	   = WinDivertSend(handle, held.data.data(), static_cast<UINT>(held.data.size()), &written, &held.address) != FALSE;
	const uint64_t after   = now_ns();
	if (ok)
	{
		++stats.sent;
		stats.send.add(before, after);
	}
	else
		++stats.send_failed;
}

// The benchmark payload starts after the IP and UDP headers; the sender's stamp is read from there
bool stamp_of(uint8_t* packet, UINT length, uint64_t& stamp)
{
	void* payload		 = nullptr;
	UINT  payload_length = 0;
	if (!WinDivertHelperParsePacket(packet, length, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &payload, &payload_length, nullptr, nullptr) ||
		payload_length < 16)
		return false;
	std::memcpy(&stamp, payload, sizeof(stamp));
	return true;
}

int run_hold(const Args& args)
{
	const long		  port		 = args.num("--port", "0");
	const bool		  forward	 = args.get("--layer", "network") == "forward";
	const long		  delay_ms	 = args.num("--delay-ms", "0");
	const long		  drop_every = args.num("--drop-every", "0");
	const long		  batch		 = std::max(1L, std::min(args.num("--batch", "1"), static_cast<long>(WINDIVERT_BATCH_MAX)));
	// Locally generated packets, loopback included, are only seen once, as outbound
	std::string filter = args.get("--filter", "");
	if (filter.empty())
		filter = "udp.DstPort == " + std::to_string(port) + (forward ? "" : " and outbound");

	HANDLE handle = WinDivertOpen(filter.c_str(), forward ? WINDIVERT_LAYER_NETWORK_FORWARD : WINDIVERT_LAYER_NETWORK, static_cast<INT16>(args.num("--priority", "0")), 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		const DWORD code = GetLastError();
		std::fprintf(stderr, "wdbench: WinDivertOpen failed (error %lu): filter \"%s\", layer %s\n", static_cast<unsigned long>(code), filter.c_str(), forward ? "forward" : "network");
		switch (code)
		{
			case ERROR_ACCESS_DENIED:
				std::fprintf(stderr, "  not elevated, or the WinDivert driver service is stale: from an admin shell try `sc stop WinDivert` and `sc delete WinDivert` (stop lagsw first), then run again\n");
				break;
			case ERROR_FILE_NOT_FOUND:
				std::fprintf(stderr, "  WinDivert64.sys was not found next to wdbench.exe\n");
				break;
			case ERROR_INVALID_IMAGE_HASH:
				std::fprintf(stderr, "  the driver signature was rejected (Secure Boot, HVCI or the vulnerable driver blocklist)\n");
				break;
			case ERROR_INVALID_PARAMETER:
				std::fprintf(stderr, "  the filter does not compile for this layer\n");
				break;
		}
		return 1;
	}
	// Defaults are the values lagsw uses (backends/windivert/backend.cc)
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, static_cast<UINT64>(args.num("--queue-length", "4096")));
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, static_cast<UINT64>(args.num("--queue-time-ms", "1024")));

	g_divert = handle;
	SetConsoleCtrlHandler(on_signal, TRUE);
	stop_after(args.num("--seconds", "0"));
	timeBeginPeriod(1);

	HoldStats				stats;
	std::mutex				mutex;
	std::condition_variable wake;
	std::deque<Held>		queue;
	bool					reader_done = false;

	// With a delay the verdicts come from a second thread, like the engine's scheduler; without one they are sent inline
	std::thread writer;
	if (delay_ms > 0)
		writer = std::thread([&] {
			for (;;)
			{
				Held held;
				{
					std::unique_lock<std::mutex> lock(mutex);
					wake.wait(lock, [&] { return !queue.empty() || reader_done; });
					if (queue.empty())
						return;
					held = std::move(queue.front());
					queue.pop_front();
				}
				for (;;)
				{
					const uint64_t now = now_ns();
					if (now >= held.due_ns)
						break;
					const uint64_t remaining_us = (held.due_ns - now) / 1000;
					if (remaining_us > 2000)
						Sleep(static_cast<DWORD>(remaining_us / 1000 - 1));
					else
						YieldProcessor();
				}
				stats.over.add(held.due_ns, now_ns());
				send_one(handle, held, stats);
			}
		});

	std::vector<uint8_t>		   buffer(static_cast<size_t>(batch) * 0xFFFF);
	std::vector<WINDIVERT_ADDRESS> addresses(static_cast<size_t>(batch));
	uint64_t					   counter = 0;
	while (!g_stop)
	{
		UINT length = 0, address_bytes = static_cast<UINT>(addresses.size() * sizeof(WINDIVERT_ADDRESS));
		if (!WinDivertRecvEx(handle, buffer.data(), static_cast<UINT>(buffer.size()), &length, 0, addresses.data(), &address_bytes, nullptr))
		{
			const DWORD code = GetLastError();
			if (code == ERROR_NO_DATA || code == ERROR_INVALID_HANDLE || code == ERROR_OPERATION_ABORTED)
				break;
			continue;
		}
		const uint64_t recv_ns = now_ns();

		const size_t	  count	 = address_bytes / sizeof(WINDIVERT_ADDRESS);
		uint8_t*		  packet = buffer.data();
		UINT			  remaining = length;
		std::vector<Held> immediate;
		for (size_t i = 0; i < count && remaining > 0; ++i)
		{
			void* next		= nullptr;
			UINT  next_size = 0;
			if (!WinDivertHelperParsePacket(packet, remaining, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &next, &next_size))
				break;
			const UINT packet_size = remaining - next_size;
			++stats.captured;
			uint64_t stamp;
			if (stamp_of(packet, packet_size, stamp))
				stats.cap.add(stamp, recv_ns);
			if (drop_every > 0 && ++counter % static_cast<uint64_t>(drop_every) == 0)
				++stats.dropped;
			else
			{
				Held held;
				held.data.assign(packet, packet + packet_size);
				held.address = addresses[i];
				held.due_ns	 = recv_ns + static_cast<uint64_t>(delay_ms) * 1000000ull;
				if (delay_ms > 0)
				{
					{
						std::lock_guard<std::mutex> lock(mutex);
						queue.push_back(std::move(held));
					}
					wake.notify_one();
				}
				else
				{
					stats.over.add(held.due_ns, now_ns());
					immediate.push_back(std::move(held));
				}
			}
			packet	  = static_cast<uint8_t*>(next);
			remaining = next_size;
		}
		if (immediate.size() == 1 || batch == 1)
			for (const Held& held : immediate)
				send_one(handle, held, stats);
		else if (!immediate.empty())
		{
			// One call re-injects the whole batch
			std::vector<uint8_t>		   joined;
			std::vector<WINDIVERT_ADDRESS> joined_addresses;
			for (const Held& held : immediate)
			{
				joined.insert(joined.end(), held.data.begin(), held.data.end());
				joined_addresses.push_back(held.address);
			}
			UINT		   written = 0;
			const uint64_t before  = now_ns();
			const bool	   ok = WinDivertSendEx(handle, joined.data(), static_cast<UINT>(joined.size()), &written, 0, joined_addresses.data(), static_cast<UINT>(joined_addresses.size() * sizeof(WINDIVERT_ADDRESS)), nullptr) != FALSE;
			const uint64_t after = now_ns();
			if (ok)
			{
				stats.sent += immediate.size();
				stats.send.add(before, after);
			}
			else
				stats.send_failed += immediate.size();
		}
	}
	{
		std::lock_guard<std::mutex> lock(mutex);
		reader_done = true;
	}
	wake.notify_all();
	if (writer.joinable())
		writer.join();
	g_divert = INVALID_HANDLE_VALUE;
	WinDivertClose(handle);
	timeEndPeriod(1);

	std::printf("captured=%llu sent=%llu dropped=%llu send_failed=%llu cpu_ms=%.1f",
				static_cast<unsigned long long>(stats.captured),
				static_cast<unsigned long long>(stats.sent),
				static_cast<unsigned long long>(stats.dropped),
				static_cast<unsigned long long>(stats.send_failed),
				cpu_ms_self());
	stats.cap.print("cap");
	stats.over.print("over");
	stats.send.print("send");
	std::printf("\n");
	return 0;
}
}  // namespace

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		std::fprintf(stderr, "usage: wdbench flood|sink|hold ... (see the header of wdbench.cc)\n");
		return 2;
	}
	Args args;
	for (int i = 2; i < argc; ++i)
		args.v.emplace_back(argv[i]);
	const std::string command = argv[1];
	if (command == "flood")
		return run_flood(args);
	if (command == "sink")
		return run_sink(args);
	if (command == "hold")
		return run_hold(args);
	std::fprintf(stderr, "wdbench: unknown command %s\n", command.c_str());
	return 2;
}
