// Phase 2 benchmark tools (pocs/linux_kernel_module_backend.md §12): a paced UDP sender, a counting sink and three
// capture-only sniffers that look at the same forwarded packets: the swdivert ring, AF_PACKET TPACKET_V3 and NFQUEUE.
// All results are printed as one `key=value` line, parsed by bench.py.
//   swbench flood  --dst IP --port P --pps N --seconds S --size B
//   swbench sink   --port P
//   swbench sniff  --mode swdiv|afpacket|nfq --port P [--iface IF] [--snap B] [--slots N]
//   swbench sniff  --mode swdiv-hold|nfq-hold --port P [--proto udp|tcp] [--delay-ms D] [--drop-every K] [--batch yes]
//   swbench tcpsink --port P            one connection: prints bytes, an FNV-1a hash and the peer address
//   swbench tcpsend --dst IP --port P --bytes N [--seed S]
// sink and sniff run until SIGINT/SIGTERM and then print their result. The -hold modes give every packet a verdict D ms after it
// was captured (0: at once; -1: never, so only the module's timeout or its close releases it) and drop every K-th packet.
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#include "swdivert_ring.h"

namespace {
std::atomic<bool> g_stop{false};

void on_signal(int)
{
	g_stop = true;
}

[[noreturn]] void die(const char* what)
{
	std::fprintf(stderr, "swbench: %s: %s\n", what, std::strerror(errno));
	std::exit(1);
}

[[noreturn]] void usage()
{
	std::fprintf(stderr, "usage: swbench flood|sink|sniff ... (see the header of swbench.cc)\n");
	std::exit(2);
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
			std::fprintf(stderr, "swbench: missing %s\n", name);
			std::exit(2);
		}
		return fallback;
	}
	long num(const char* name, const char* fallback = nullptr) const { return std::atol(get(name, fallback).c_str()); }
};

uint64_t now_ns()
{
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
}

void install_signals()
{
	struct sigaction action = {};
	action.sa_handler		= on_signal;
	sigaction(SIGINT, &action, nullptr);
	sigaction(SIGTERM, &action, nullptr);
}

double cpu_ms_self()
{
	rusage usage;
	getrusage(RUSAGE_SELF, &usage);
	return static_cast<double>(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1000.0 +
		   static_cast<double>(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1000.0;
}

void announce_ready()
{
	std::printf("ready\n");
	std::fflush(stdout);
}

// ---- flood and sink ----

int run_flood(const Args& args)
{
	const std::string dst	  = args.get("--dst");
	const long		  port	  = args.num("--port");
	const long		  pps	  = args.num("--pps");
	const long		  seconds = args.num("--seconds");
	const long		  size	  = args.num("--size", "512");
	const uint64_t	  stream  = static_cast<uint64_t>(args.num("--stream", "0")) & 7; // lets several floods share one sink

	const int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		die("socket");
	int sndbuf = 8 << 20;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	sockaddr_in to = {};
	to.sin_family  = AF_INET;
	to.sin_port	   = htons(static_cast<uint16_t>(port));
	inet_pton(AF_INET, dst.c_str(), &to.sin_addr);
	if (connect(fd, reinterpret_cast<sockaddr*>(&to), sizeof(to)) < 0)
		die("connect");

	if (size < 16)
	{
		std::fprintf(stderr, "swbench: --size must be at least 16 (timestamp and sequence number)\n");
		return 2;
	}
	std::vector<char> payload(static_cast<size_t>(size), 'x');
	const uint64_t	  start	   = now_ns();
	const uint64_t	  end	   = start + static_cast<uint64_t>(seconds) * 1000000000ull;
	const double	  interval = 1e9 / static_cast<double>(pps);
	uint64_t		  sent	   = 0;
	uint64_t		  failed   = 0;
	for (;;)
	{
		const uint64_t now = now_ns();
		if (now >= end)
			break;
		// Everything that should have been sent by now goes out in one burst; this keeps the average rate exact
		const uint64_t due = static_cast<uint64_t>(static_cast<double>(now - start) / interval) + 1;
		if (sent + failed >= due)
		{
			// A short sleep instead of spinning, so the sender's own CPU stays small and comparable between runs
			timespec nap = {0, 20000};
			nanosleep(&nap, nullptr);
			continue;
		}
		while (sent + failed < due)
		{
			// Bytes 0-7: send time (CLOCK_MONOTONIC, ns; the namespaces share the clock), 8-15: sequence number, rest: 'x'
			const uint64_t stamp = now_ns();
			const uint64_t seq	 = (stream << 32) | (sent + failed);
			std::memcpy(payload.data(), &stamp, sizeof(stamp));
			std::memcpy(payload.data() + 8, &seq, sizeof(seq));
			if (send(fd, payload.data(), payload.size(), 0) < 0)
				++failed;
			else
				++sent;
		}
	}
	std::printf("sent=%llu failed=%llu cpu_ms=%.1f\n",
				static_cast<unsigned long long>(sent),
				static_cast<unsigned long long>(failed),
				cpu_ms_self());
	return 0;
}

int run_sink(const Args& args)
{
	const long port	  = args.num("--port");
	const bool verify = args.get("--verify", "no") != "no";
	const int  fd	  = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		die("socket");
	int rcvbuf = 32 << 20;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	sockaddr_in addr = {};
	addr.sin_family	 = AF_INET;
	addr.sin_port	 = htons(static_cast<uint16_t>(port));
	if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
		die("bind");
	install_signals();
	announce_ready();

	constexpr unsigned kBatch = 64;
	static char		   buffers[kBatch][2048];
	mmsghdr			   msgs[kBatch];
	iovec			   iov[kBatch];
	uint64_t		   received = 0, corrupt = 0, dups = 0, reordered = 0;
	uint64_t			   max_seq[8] = {};
	std::vector<uint32_t> latency_us;
	std::vector<uint8_t>  seen[8]; // per flood stream (the high bits of the sequence number)
	latency_us.reserve(1 << 20);
	while (!g_stop)
	{
		for (unsigned i = 0; i < kBatch; ++i)
		{
			iov[i]					   = {buffers[i], sizeof(buffers[i])};
			msgs[i]					   = {};
			msgs[i].msg_hdr.msg_iov	   = &iov[i];
			msgs[i].msg_hdr.msg_iovlen = 1;
		}
		pollfd pfd = {fd, POLLIN, 0};
		if (poll(&pfd, 1, 100) <= 0)
			continue;
		const int count = recvmmsg(fd, msgs, kBatch, MSG_DONTWAIT, nullptr);
		const uint64_t now = now_ns();
		for (int i = 0; i < count; ++i)
		{
			++received;
			const unsigned len = msgs[i].msg_len;
			if (len < 16)
			{
				++corrupt;
				continue;
			}
			uint64_t stamp, seq;
			std::memcpy(&stamp, buffers[i], sizeof(stamp));
			std::memcpy(&seq, buffers[i] + 8, sizeof(seq));
			latency_us.push_back(static_cast<uint32_t>(std::min<uint64_t>((now - stamp) / 1000, 0xFFFFFFFFull)));
			if (verify)
				for (unsigned b = 16; b < len; ++b)
					if (buffers[i][b] != 'x')
					{
						++corrupt;
						break;
					}
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
	}
	std::sort(latency_us.begin(), latency_us.end());
	auto pct = [&](double p) { return latency_us.empty() ? 0u : latency_us[static_cast<size_t>(p * static_cast<double>(latency_us.size() - 1))]; };
	std::printf("received=%llu cpu_ms=%.1f lat_p50_us=%u lat_p99_us=%u lat_max_us=%u corrupt=%llu dups=%llu reordered=%llu\n",
				static_cast<unsigned long long>(received),
				cpu_ms_self(),
				pct(0.50),
				pct(0.99),
				latency_us.empty() ? 0u : latency_us.back(),
				static_cast<unsigned long long>(corrupt),
				static_cast<unsigned long long>(dups),
				static_cast<unsigned long long>(reordered));
	return 0;
}

// ---- TCP: a deterministic stream through the gateway, to check that held and resumed packets keep a connection intact ----

uint64_t fnv1a(uint64_t hash, const unsigned char* data, size_t size)
{
	for (size_t i = 0; i < size; ++i)
		hash = (hash ^ data[i]) * 1099511628211ull;
	return hash;
}

int run_tcpsink(const Args& args)
{
	const long port = args.num("--port");
	const int  lfd	= socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
		die("socket");
	int one = 1;
	setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	sockaddr_in addr = {};
	addr.sin_family	 = AF_INET;
	addr.sin_port	 = htons(static_cast<uint16_t>(port));
	if (bind(lfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 || listen(lfd, 1) < 0)
		die("bind/listen");
	announce_ready();
	sockaddr_in peer	 = {};
	socklen_t	peer_len = sizeof(peer);
	const int	fd		 = accept(lfd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
	if (fd < 0)
		die("accept");
	std::vector<unsigned char> buffer(1 << 16);
	uint64_t				   total = 0, hash = 14695981039346656037ull;
	for (;;)
	{
		const ssize_t count = recv(fd, buffer.data(), buffer.size(), 0);
		if (count <= 0)
			break;
		total += static_cast<uint64_t>(count);
		hash = fnv1a(hash, buffer.data(), static_cast<size_t>(count));
	}
	char text[INET_ADDRSTRLEN] = {};
	inet_ntop(AF_INET, &peer.sin_addr, text, sizeof(text));
	std::printf("bytes=%llu hash=%llu peer=%s\n", static_cast<unsigned long long>(total), static_cast<unsigned long long>(hash), text);
	return 0;
}

int run_tcpsend(const Args& args)
{
	const std::string dst	= args.get("--dst");
	const long		  port	= args.num("--port");
	const uint64_t	  bytes = static_cast<uint64_t>(args.num("--bytes"));
	uint64_t		  state = static_cast<uint64_t>(args.num("--seed", "88172645463325252"));
	const int		  fd	= socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		die("socket");
	sockaddr_in to = {};
	to.sin_family  = AF_INET;
	to.sin_port	   = htons(static_cast<uint16_t>(port));
	inet_pton(AF_INET, dst.c_str(), &to.sin_addr);
	const uint64_t started = now_ns();
	if (connect(fd, reinterpret_cast<sockaddr*>(&to), sizeof(to)) < 0)
		die("connect");
	std::vector<unsigned char> buffer(1 << 15);
	uint64_t				   sent = 0, hash = 14695981039346656037ull;
	while (sent < bytes)
	{
		const size_t chunk = static_cast<size_t>(std::min<uint64_t>(buffer.size(), bytes - sent));
		for (size_t i = 0; i < chunk; ++i)
		{
			state ^= state << 13;
			state ^= state >> 7;
			state ^= state << 17;
			buffer[i] = static_cast<unsigned char>(state);
		}
		size_t off = 0;
		while (off < chunk)
		{
			const ssize_t count = send(fd, buffer.data() + off, chunk - off, 0);
			if (count <= 0)
				die("send");
			off += static_cast<size_t>(count);
		}
		hash = fnv1a(hash, buffer.data(), chunk);
		sent += chunk;
	}
	shutdown(fd, SHUT_WR);
	// Wait for the peer to close, so the time covers delivery of everything
	char drain[16];
	while (recv(fd, drain, sizeof(drain), 0) > 0) {}
	std::printf("sent=%llu hash=%llu elapsed_ms=%.0f\n", static_cast<unsigned long long>(sent), static_cast<unsigned long long>(hash), static_cast<double>(now_ns() - started) / 1e6);
	return 0;
}

// ---- sniffers ----

struct SniffResult
{
	uint64_t captured = 0;
	uint64_t dropped  = 0;
	uint64_t bytes	  = 0;
	uint64_t polls	  = 0; // poll() calls that had to wait, i.e. how often the reader went to sleep
	uint64_t wakeups  = 0; // kernel-side wake_up() calls (swdivert only)
};

void print_result(const SniffResult& result, double cpu_ms)
{
	std::printf("captured=%llu dropped=%llu bytes=%llu cpu_ms=%.1f polls=%llu wakeups=%llu\n",
				static_cast<unsigned long long>(result.captured),
				static_cast<unsigned long long>(result.dropped),
				static_cast<unsigned long long>(result.bytes),
				cpu_ms,
				static_cast<unsigned long long>(result.polls),
				static_cast<unsigned long long>(result.wakeups));
}

// Verdicts of the hold modes, sent in batches (one ioctl per drain of the ring)
struct HoldState
{
	int								 fd = -1;
	std::deque<std::pair<uint64_t, uint64_t>> pending; // (id, due time in ns), in due order because the delay is constant
	std::vector<swdiv_verdict>		 batch;
	uint64_t						 seen = 0, resumed = 0, dropped = 0, enoent = 0, errors = 0;
};

void flush_verdicts(HoldState& hold)
{
	size_t offset = 0;
	while (offset < hold.batch.size())
	{
		const size_t		count = std::min<size_t>(SWDIV_MAX_VERDICTS, hold.batch.size() - offset);
		swdiv_verdict_args	args  = {};
		args.items				  = static_cast<__u64>(reinterpret_cast<uintptr_t>(hold.batch.data() + offset));
		args.count				  = static_cast<__u32>(count);
		if (ioctl(hold.fd, SWDIVERT_IOC_VERDICT, &args) < 0)
		{
			++hold.errors;
		}
		else
		{
			for (size_t i = 0; i < count; ++i)
			{
				const swdiv_verdict& verdict = hold.batch[offset + i];
				if (verdict.status == 0)
					(verdict.verdict == SWDIV_V_DROP ? hold.dropped : hold.resumed)++;
				else if (verdict.status == ENOENT)
					++hold.enoent;
				else
					++hold.errors;
			}
		}
		offset += count;
	}
	hold.batch.clear();
}

// The ring: poll() to sleep, then drain everything that is published. With `hold` the packets are stolen and every one gets a verdict.
int sniff_swdiv(const Args& args, bool hold_mode)
{
	const long delay_ms	  = args.num("--delay-ms", "0");
	const long drop_every = args.num("--drop-every", "0");
	const long port	 = args.num("--port");
	const long snap	 = args.num("--snap", "224");
	const long slots = args.num("--slots", "16384");

	const int fd = open("/dev/" SWDIVERT_DEVICE_NAME, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		die("open /dev/" SWDIVERT_DEVICE_NAME " (is the module loaded, and are you root?)");
	__u32 version = 0;
	if (ioctl(fd, SWDIVERT_IOC_VERSION, &version) < 0 || version != SWDIVERT_ABI_VERSION)
	{
		std::fprintf(stderr, "swbench: swdivert ABI mismatch (module %u, tool %d)\n", version, SWDIVERT_ABI_VERSION);
		return 1;
	}
	swdiv_open_args open_args = {};
	open_args.slots			  = static_cast<__u32>(slots);
	open_args.slot_bytes	  = static_cast<__u32>(snap + SWDIVERT_SLOT_HDR_BYTES);
	open_args.flags			  = hold_mode ? SWDIV_OPEN_HOLD : 0;
	if (ioctl(fd, SWDIVERT_IOC_OPEN, &open_args) < 0)
		die("SWDIVERT_IOC_OPEN");
	void* data = mmap(nullptr, open_args.data_bytes, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED)
		die("mmap ring");
	void* cons = mmap(nullptr,
					  static_cast<size_t>(sysconf(_SC_PAGESIZE)),
					  PROT_READ | PROT_WRITE,
					  MAP_SHARED,
					  fd,
					  static_cast<off_t>(open_args.cons_offset));
	if (cons == MAP_FAILED)
		die("mmap consumer page");
	swdiv_tuple tuple = {};
	tuple.proto		  = args.get("--proto", "udp") == "tcp" ? IPPROTO_TCP : IPPROTO_UDP;
	tuple.dport		  = htons(static_cast<uint16_t>(port));
	if (ioctl(fd, SWDIVERT_IOC_SET_FILTER, &tuple) < 0)
		die("SWDIVERT_IOC_SET_FILTER");

	swdiv_ring_view view;
	swdiv_ring_view_init(&view, data, open_args.hdr_bytes, static_cast<swdiv_cons*>(cons));
	install_signals();
	if (ioctl(fd, SWDIVERT_IOC_START) < 0)
		die("SWDIVERT_IOC_START");
	announce_ready();

	SniffResult result;
	HoldState	hold;
	hold.fd = fd;
	while (!g_stop)
	{
		const __u32 avail = swdiv_ring_avail(&view);
		if (avail != 0)
		{
			volatile unsigned char sink = 0;
			const uint64_t		   now	= hold_mode ? now_ns() : 0;
			for (__u32 i = 0; i < avail; ++i)
			{
				const swdiv_slot_hdr* slot = swdiv_ring_slot(&view, i);
				result.bytes += slot->len;
				sink = sink + swdiv_slot_data(slot)[0];	 // touch the packet like a real consumer would
				if (!hold_mode || !(slot->flags & SWDIV_SLOT_F_HELD))
					continue;
				++hold.seen;
				if (drop_every > 0 && hold.seen % static_cast<uint64_t>(drop_every) == 0)
					hold.batch.push_back({slot->id, SWDIV_V_DROP, 0});
				else if (delay_ms == 0)
					hold.batch.push_back({slot->id, SWDIV_V_RESUME, 0});
				else if (delay_ms > 0)
					hold.pending.emplace_back(slot->id, now + static_cast<uint64_t>(delay_ms) * 1000000ull);
				// delay_ms < 0: no verdict, ever
			}
			(void)sink;
			result.captured += avail;
			swdiv_ring_release(&view, avail);
		}
		int timeout_ms = 100;
		if (hold_mode)
		{
			const uint64_t now = now_ns();
			while (!hold.pending.empty() && hold.pending.front().second <= now)
			{
				hold.batch.push_back({hold.pending.front().first, SWDIV_V_RESUME, 0});
				hold.pending.pop_front();
			}
			flush_verdicts(hold);
			if (!hold.pending.empty())
				timeout_ms = static_cast<int>(std::min<uint64_t>(100, (hold.pending.front().second - now) / 1000000ull + 1));
		}
		if (avail == 0)
		{
			pollfd pfd = {fd, POLLIN, 0};
			poll(&pfd, 1, timeout_ms);
			++result.polls;
		}
	}
	// Whatever is still published counts as captured
	const __u32 rest = swdiv_ring_avail(&view);
	result.captured += rest;
	swdiv_ring_release(&view, rest);

	// Stop first: it resumes whatever is still held, which the statistics then show as `flushed`
	ioctl(fd, SWDIVERT_IOC_STOP);
	swdiv_stats stats = {};
	ioctl(fd, SWDIVERT_IOC_STATS, &stats);
	result.dropped = stats.dropped_full;
	result.wakeups = stats.wakeups;
	print_result(result, cpu_ms_self());
	if (hold_mode)
		std::printf("held=%llu resumed=%llu vdropped=%llu expired=%llu flushed=%llu dev_dropped=%llu resume_lost=%llu pass_unsupported=%llu pass_limit=%llu "
					"enoent=%llu verr=%llu\n",
					static_cast<unsigned long long>(stats.held), static_cast<unsigned long long>(stats.resumed),
					static_cast<unsigned long long>(stats.verdict_dropped), static_cast<unsigned long long>(stats.expired),
					static_cast<unsigned long long>(stats.flushed), static_cast<unsigned long long>(stats.dev_dropped),
					static_cast<unsigned long long>(stats.resume_lost), static_cast<unsigned long long>(stats.pass_unsupported),
					static_cast<unsigned long long>(stats.pass_limit), static_cast<unsigned long long>(hold.enoent),
					static_cast<unsigned long long>(hold.errors));
	return 0;
}

// AF_PACKET TPACKET_V3 on the interface the traffic enters the gateway through, with an equivalent in-kernel filter
int sniff_afpacket(const Args& args)
{
	const long		  port	= args.num("--port");
	const long		  snap	= args.num("--snap", "224");
	const std::string iface = args.get("--iface");

	const int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (fd < 0)
		die("socket AF_PACKET");
	const int version = TPACKET_V3;
	if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0)
		die("PACKET_VERSION");

	// ip && udp && dport == port; accept `14 + snap` bytes of the frame
	sock_filter code[] = {
		BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 5),
		BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 3),
		BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 36),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(port), 0, 1),
		BPF_STMT(BPF_RET | BPF_K, static_cast<uint32_t>(14 + snap)),
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	sock_fprog program = {static_cast<unsigned short>(sizeof(code) / sizeof(code[0])), code};
	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) < 0)
		die("SO_ATTACH_FILTER");

	tpacket_req3 req	  = {};
	req.tp_block_size	  = 1 << 20;
	req.tp_block_nr		  = 8;
	req.tp_frame_size	  = 2048;
	req.tp_frame_nr		  = (req.tp_block_size / req.tp_frame_size) * req.tp_block_nr;
	req.tp_retire_blk_tov = 1;
	if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0)
		die("PACKET_RX_RING");
	const size_t ring_bytes = static_cast<size_t>(req.tp_block_size) * req.tp_block_nr;
	auto*		 ring = static_cast<unsigned char*>(mmap(nullptr, ring_bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0));
	if (ring == MAP_FAILED)
		die("mmap TPACKET ring");

	sockaddr_ll bind_addr  = {};
	bind_addr.sll_family   = AF_PACKET;
	bind_addr.sll_protocol = htons(ETH_P_IP);
	bind_addr.sll_ifindex  = static_cast<int>(if_nametoindex(iface.c_str()));
	if (bind_addr.sll_ifindex == 0 || bind(fd, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0)
		die("bind AF_PACKET");
	install_signals();
	announce_ready();

	SniffResult result;
	unsigned	block = 0;
	auto		drain = [&]() {
		for (;;)
		{
			auto* desc = reinterpret_cast<tpacket_block_desc*>(ring + static_cast<size_t>(block) * req.tp_block_size);
			if (!(__atomic_load_n(&desc->hdr.bh1.block_status, __ATOMIC_ACQUIRE) & TP_STATUS_USER))
				return;
			auto* packet = reinterpret_cast<tpacket3_hdr*>(reinterpret_cast<unsigned char*>(desc) + desc->hdr.bh1.offset_to_first_pkt);
			for (uint32_t i = 0; i < desc->hdr.bh1.num_pkts; ++i)
			{
				result.bytes += packet->tp_len;
				volatile unsigned char sink = *(reinterpret_cast<unsigned char*>(packet) + packet->tp_mac);
				(void)sink;
				packet = reinterpret_cast<tpacket3_hdr*>(reinterpret_cast<unsigned char*>(packet) + packet->tp_next_offset);
			}
			result.captured += desc->hdr.bh1.num_pkts;
			__atomic_store_n(&desc->hdr.bh1.block_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE);
			block = (block + 1) % req.tp_block_nr;
		}
	};
	while (!g_stop)
	{
		pollfd pfd = {fd, POLLIN | POLLERR, 0};
		poll(&pfd, 1, 100);
		++result.polls;
		drain();
	}
	drain();
	tpacket_stats_v3 stats	= {};
	socklen_t		 length = sizeof(stats);
	getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &length);
	result.dropped = stats.tp_drops;
	print_result(result, cpu_ms_self());
	return 0;
}

struct NfqState
{
	SniffResult							result;
	bool								hold		= false;
	long								delay_ms	= 0;
	long								drop_every	= 0;
	bool								batch		= false; // one verdict for all packets of a receive, as the shipped backend does
	bool								batch_open	= false;
	uint32_t							batch_last	= 0;
	uint64_t							seen		= 0;
	std::deque<std::pair<uint32_t, uint64_t>> pending; // (packet id, due time in ns)
};

int nfq_callback(nfq_q_handle* queue, nfgenmsg*, nfq_data* packet, void* data)
{
	auto* state	 = static_cast<NfqState*>(data);
	auto* header = nfq_get_msg_packet_hdr(packet);
	if (!header)
		return 0;
	unsigned char* payload = nullptr;
	const int	   length  = nfq_get_payload(packet, &payload);
	if (length > 0)
	{
		volatile unsigned char sink = payload[0];
		(void)sink;
		state->result.bytes += static_cast<uint64_t>(length);
	}
	++state->result.captured;
	const uint32_t id = ntohl(header->packet_id);
	if (state->hold)
	{
		++state->seen;
		if (state->drop_every > 0 && state->seen % static_cast<uint64_t>(state->drop_every) == 0)
			return nfq_set_verdict(queue, id, NF_DROP, 0, nullptr);
		if (state->delay_ms > 0)
		{
			state->pending.emplace_back(id, now_ns() + static_cast<uint64_t>(state->delay_ms) * 1000000ull);
			return 0;
		}
		if (state->delay_ms < 0)
			return 0; // never: the kernel drops it when the listener goes away
		if (state->batch && state->drop_every == 0)
		{
			state->batch_open = true;
			state->batch_last = id;
			return 0;
		}
	}
	// A sniffer on NFQUEUE has to give a verdict for every packet: this is the round trip the module removes
	return nfq_set_verdict(queue, id, NF_ACCEPT, 0, nullptr);
}

// NFQUEUE: the nft rule (installed by bench.py) queues matching packets to queue 0 with `bypass`
int sniff_nfq(const Args& args, bool hold_mode)
{
	const long	snap   = args.num("--snap", "224");
	nfq_handle* handle = nfq_open();
	if (!handle)
		die("nfq_open");
	NfqState	  state;
	state.hold		= hold_mode;
	state.delay_ms	= args.num("--delay-ms", "0");
	state.drop_every = args.num("--drop-every", "0");
	state.batch		 = args.get("--batch", "no") != "no";
	nfq_q_handle* queue = nfq_create_queue(handle, 0, &nfq_callback, &state);
	if (!queue)
		die("nfq_create_queue");
	if (nfq_set_mode(queue, NFQNL_COPY_PACKET, static_cast<uint32_t>(snap)) < 0)
		die("nfq_set_mode");
	nfq_set_queue_maxlen(queue, 16384);
	const int fd	 = nfq_fd(handle);
	int		  rcvbuf = 32 << 20;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf));
	nfnl_rcvbufsiz(nfq_nfnlh(handle), 32u << 20);
	install_signals();
	announce_ready();

	std::vector<char> buffer(1 << 16);
	while (!g_stop)
	{
		int timeout_ms = 100;
		if (!state.pending.empty())
		{
			const uint64_t now = now_ns();
			while (!state.pending.empty() && state.pending.front().second <= now)
			{
				nfq_set_verdict(queue, state.pending.front().first, NF_ACCEPT, 0, nullptr);
				state.pending.pop_front();
			}
			if (!state.pending.empty())
				timeout_ms = static_cast<int>(std::min<uint64_t>(100, (state.pending.front().second - now) / 1000000ull + 1));
		}
		pollfd pfd = {fd, POLLIN, 0};
		if (poll(&pfd, 1, timeout_ms) <= 0)
			continue;
		++state.result.polls;
		const ssize_t count = recv(fd, buffer.data(), buffer.size(), MSG_DONTWAIT);
		if (count > 0)
		{
			nfq_handle_packet(handle, buffer.data(), static_cast<int>(count));
			if (state.batch_open)
			{
				// Accepts every packet up to the last id of this receive in one message
				nfq_set_verdict_batch(queue, state.batch_last, NF_ACCEPT);
				state.batch_open = false;
			}
		}
		else if (count < 0 && errno == ENOBUFS)
			++state.result.dropped;	 // the socket buffer overflowed: the kernel dropped notifications (bypass lets the packets through)
	}
	print_result(state.result, cpu_ms_self());
	nfq_destroy_queue(queue);
	nfq_close(handle);
	return 0;
}

int run_sniff(const Args& args)
{
	const std::string mode = args.get("--mode");
	if (mode == "swdiv")
		return sniff_swdiv(args, false);
	if (mode == "swdiv-hold")
		return sniff_swdiv(args, true);
	if (mode == "afpacket")
		return sniff_afpacket(args);
	if (mode == "nfq")
		return sniff_nfq(args, false);
	if (mode == "nfq-hold")
		return sniff_nfq(args, true);
	usage();
}
}  // namespace

int main(int argc, char** argv)
{
	if (argc < 2)
		usage();
	Args args;
	for (int i = 2; i < argc; ++i)
		args.v.emplace_back(argv[i]);
	const std::string command = argv[1];
	if (command == "flood")
		return run_flood(args);
	if (command == "sink")
		return run_sink(args);
	if (command == "sniff")
		return run_sniff(args);
	if (command == "tcpsink")
		return run_tcpsink(args);
	if (command == "tcpsend")
		return run_tcpsend(args);
	usage();
}
