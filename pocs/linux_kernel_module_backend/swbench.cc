// Phase 2 benchmark tools (pocs/linux_kernel_module_backend.md §12): a paced UDP sender, a counting sink and three
// capture-only sniffers that look at the same forwarded packets: the swdivert ring, AF_PACKET TPACKET_V3 and NFQUEUE.
// All results are printed as one `key=value` line, parsed by bench.py.
//   swbench flood  --dst IP --port P --pps N --seconds S --size B
//   swbench sink   --port P
//   swbench sniff  --mode swdiv|afpacket|nfq --port P [--iface IF] [--snap B] [--slots N]
//   swbench sniff  --mode swdiv-hold|nfq-hold --port P [--proto udp|tcp] [--delay-ms D] [--drop-every K] [--batch yes] [--modify payload]
//   swbench sniff  --mode swdiv-hold ... [--prio N] [--snap B] [--modify payload|grow|shrink|dport|dst|bad] [--to-port P] [--to-ip IP]
//                                        [--twin yes --inject-if IF]   modify every held packet / inject a copy of it before resuming
//   swbench sniff  ... [--filter "WinDivert-style filter"] [--filter2 F2 --swap-ms T]   filter program instead of --port/--proto; F2
//   replaces it after T ms swbench vmcheck [--filters N --packets M --seed S]   kernel against the reference evaluator, on packets injected
//   through the rig swbench progcheck                       what SET_PROGRAM must accept and refuse swbench pktcheck --port P --iface IF
//   verifies IP and UDP checksums of the packets arriving on IF (AF_PACKET) swbench tcpsink --port P            one connection: prints
//   bytes, an FNV-1a hash and the peer address swbench tcpsend --dst IP --port P --bytes N [--seed S]
//   swbench backend --filter F [--forward yes] [--include-forward yes] [--sniff yes] [--priority N] [--delay-ms D] [--batch yes]
//                   [--discard-every K] [--modify dport --to-port P] [--seconds S]   the backend::open() channel, as the engine uses it
//   swbench backend-load | backend-api       module loading by check_privileges(); the backend contract that needs no traffic
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

#include "filter_program.h"
#include "support.h"
#include "swdivert_ring.h"

// backend_cmd.cc: the lagsw backend itself (backends/kmod), driven like the engine drives it
int run_backend(const std::vector<std::string>& arguments);
int run_backend_load(const std::vector<std::string>& arguments);
int run_backend_api(const std::vector<std::string>& arguments);

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
	const uint64_t	  stream  = static_cast<uint64_t>(args.num("--stream", "0")) & 7;  // lets several floods share one sink

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
	const char fill	  = args.get("--fill", "x")[0];
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

	constexpr unsigned	  kBatch = 64;
	static char			  buffers[kBatch][2048];
	mmsghdr				  msgs[kBatch];
	iovec				  iov[kBatch];
	uint64_t			  received = 0, corrupt = 0, dups = 0, reordered = 0;
	uint64_t			  max_seq[8] = {};
	unsigned			  len_min = 0xFFFFFFFFu, len_max = 0;
	std::vector<uint32_t> latency_us;
	std::vector<uint8_t>  seen[8];	// per flood stream (the high bits of the sequence number)
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
		const int	   count = recvmmsg(fd, msgs, kBatch, MSG_DONTWAIT, nullptr);
		const uint64_t now	 = now_ns();
		for (int i = 0; i < count; ++i)
		{
			++received;
			const unsigned len = msgs[i].msg_len;
			len_min			   = std::min(len_min, len);
			len_max			   = std::max(len_max, len);
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
					if (buffers[i][b] != fill)
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
	auto pct = [&](double p) {
		return latency_us.empty() ? 0u : latency_us[static_cast<size_t>(p * static_cast<double>(latency_us.size() - 1))];
	};
	std::printf(
		"received=%llu cpu_ms=%.1f lat_p50_us=%u lat_p99_us=%u lat_max_us=%u corrupt=%llu dups=%llu reordered=%llu len_min=%u len_max=%u\n",
		static_cast<unsigned long long>(received),
		cpu_ms_self(),
		pct(0.50),
		pct(0.99),
		latency_us.empty() ? 0u : latency_us.back(),
		static_cast<unsigned long long>(corrupt),
		static_cast<unsigned long long>(dups),
		static_cast<unsigned long long>(reordered),
		received ? len_min : 0u,
		len_max);
	return 0;
}

// ---- filter programs ----

// Compiles a filter string with the user-space compiler (the NFQUEUE backend's parser and DNF conversion) and installs the program.
bool install_filter(int fd, const std::string& text)
{
	kmodf::Program program;
	std::string	   error;
	uint32_t	   position = 0;
	if (!kmodf::compile_program(text, program, error, position))
	{
		std::fprintf(stderr, "swbench: filter '%s': %s (at %u)\n", text.c_str(), error.c_str(), position);
		return false;
	}
	const std::string verdict = kmodf::verify_program(program);
	if (!verdict.empty())
	{
		std::fprintf(stderr, "swbench: filter '%s': %s\n", text.c_str(), verdict.c_str());
		return false;
	}
	if (kmodf::install_program(fd, program) < 0)
	{
		std::fprintf(stderr, "swbench: filter '%s': SWDIVERT_IOC_SET_PROGRAM: %s\n", text.c_str(), std::strerror(errno));
		return false;
	}
	return true;
}

// A handle with a ring and no reader, started: enough to count what a filter matches (and, with `priority`, to inject)
int open_counting_handle(int priority)
{
	const int fd = open("/dev/" SWDIVERT_DEVICE_NAME, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		die("open /dev/" SWDIVERT_DEVICE_NAME);
	swdiv_open_args open_args = {};
	open_args.slots			  = 64;
	open_args.slot_bytes	  = 2048 + SWDIVERT_SLOT_HDR_BYTES;
	open_args.priority		  = priority;
	if (ioctl(fd, SWDIVERT_IOC_OPEN, &open_args) < 0)
		die("SWDIVERT_IOC_OPEN");
	if (ioctl(fd, SWDIVERT_IOC_START) < 0)
		die("SWDIVERT_IOC_START");
	return fd;
}

// A packet that survives everything in front of the FORWARD hook (valid header and checksum after the kernel recomputes it, a time to live
// above 1, a destination the gateway routes to the server link) and still varies in what the filters look at.
vmtest::Bytes forwardable_packet(vmtest::Rng& rng)
{
	using vmtest::pick;
	vmtest::PacketSpec	 spec;
	static const uint8_t protos[] = {6, 6, 6, 17, 17, 17, 1, 47};
	spec.proto					  = protos[rng.below(8)];
	spec.src					  = pick(rng, vmtest::addr_pool());
	spec.dst					  = 0x0A0A0200 | (2 + rng.below(4));  // 10.10.2.2 .. 10.10.2.5
	spec.sport					  = pick(rng, vmtest::port_pool());
	spec.dport					  = pick(rng, vmtest::port_pool());
	spec.ttl					  = static_cast<uint8_t>(2 + rng.below(60));
	spec.ip_options				  = rng.chance(15) ? 1 + rng.below(2) : 0;	// zero bytes: an options list that ends at once
	spec.tcp_flags				  = static_cast<uint8_t>(rng.below(64));
	spec.tcp_doff				  = 5 + rng.below(3);
	spec.frag					  = rng.chance(88) ? 0 : (rng.chance(50) ? 0x2000 : 1 + rng.below(100));
	spec.payload.resize(rng.chance(80) ? rng.below(60) : rng.below(380));
	for (uint8_t& byte : spec.payload)
		byte = static_cast<uint8_t>(rng.next());
	return vmtest::build(spec);
}

// The kernel's decision against the reference evaluator, packet by packet: random filters, compiled and installed, and random packets
// injected on the client link. A second handle injects (a handle never sees what it injects itself) and the handle under test counts.
int run_vmcheck(const Args& args)
{
	const long	   filters	  = args.num("--filters", "40");
	const long	   per_filter = args.num("--packets", "100");
	vmtest::Rng	   rng(static_cast<uint64_t>(args.num("--seed", "7")));
	const unsigned vc = if_nametoindex("vc"), vs = if_nametoindex("vs");
	if (!vc || !vs)
	{
		std::fprintf(stderr, "swbench: vmcheck needs the client/server rig (interfaces vc and vs)\n");
		return 2;
	}
	vmtest::addr_pool() = {0x0A0A0102, 0x0A0A0105, 0x0A0A0202, 0x0A0A0203, 0x0A0A0204, 0x0A0A0209};
	vmtest::if_pool()	= {vc, vs, 999};

	const int under_test = open_counting_handle(0);
	const int injector	 = open_counting_handle(100);  // served first, so the handle under test sees its packets
	uint64_t  compiled = 0, packets = 0, visited = 0, matched = 0, dropped_early = 0, odd = 0, mismatches = 0, user_mismatches = 0;

	for (long f = 0; f < filters; ++f)
	{
		const std::string text = vmtest::random_filter(rng, 1 + rng.below(3));
		kmodf::Program	  program;
		std::string		  error;
		uint32_t		  position = 0;
		if (!kmodf::compile_program(text, program, error, position))
			continue;
		if (kmodf::install_program(under_test, program) < 0)
		{
			std::fprintf(stderr,
						 "vmcheck: the kernel refused a program the user-space verifier accepted: '%s': %s\n",
						 text.c_str(),
						 std::strerror(errno));
			return 1;
		}
		++compiled;
		const linux_shared::Node tree = linux_shared::parse_filter(text);
		for (long i = 0; i < per_filter; ++i)
		{
			const vmtest::Bytes packet = forwardable_packet(rng);
			vmtest::Meta		meta;
			meta.in_ifindex		= vc;
			meta.out_ifindex	= vs;
			const bool expected = vmtest::reference(tree, false, vmtest::facts_of(packet, meta));
			if (vmtest::run(program, packet, meta) != expected)
				++user_mismatches;

			swdiv_stats before = {}, after = {};
			ioctl(under_test, SWDIVERT_IOC_STATS, &before);
			swdiv_inject_args inject = {};
			inject.data				 = static_cast<__u64>(reinterpret_cast<uintptr_t>(packet.data()));
			inject.len				 = static_cast<__u32>(packet.size());
			inject.flags			 = SWDIV_CALC_IP | SWDIV_CALC_L4;
			inject.ifindex			 = vc;
			if (ioctl(injector, SWDIVERT_IOC_INJECT, &inject) < 0)
			{
				++dropped_early;
				continue;
			}
			ioctl(under_test, SWDIVERT_IOC_STATS, &after);
			++packets;
			const uint64_t seen = after.seen - before.seen, hit = after.matched - before.matched;
			if (seen == 0)
			{
				++dropped_early;  // the stack dropped it before the hook (nothing to compare)
			}
			else if (seen == 1)
			{
				++visited;
				matched += hit;
				if ((hit == 1) != expected)
				{
					if (++mismatches <= 5)
						std::fprintf(stderr,
									 "vmcheck MISMATCH: filter '%s': kernel %s, reference %s, packet of %zu bytes (proto %d)\n",
									 text.c_str(),
									 hit ? "matched" : "did not match",
									 expected ? "matches" : "does not match",
									 packet.size(),
									 packet[9]);
				}
			}
			else
			{
				++odd;
			}
		}
	}
	std::printf(
		"vmcheck_filters=%llu vmcheck_packets=%llu vmcheck_visited=%llu vmcheck_matched=%llu vmcheck_dropped_early=%llu vmcheck_odd=%llu "
		"vmcheck_mismatches=%llu "
		"vmcheck_user_mismatches=%llu\n",
		static_cast<unsigned long long>(compiled),
		static_cast<unsigned long long>(packets),
		static_cast<unsigned long long>(visited),
		static_cast<unsigned long long>(matched),
		static_cast<unsigned long long>(dropped_early),
		static_cast<unsigned long long>(odd),
		static_cast<unsigned long long>(mismatches),
		static_cast<unsigned long long>(user_mismatches));
	return mismatches == 0 && user_mismatches == 0 && odd == 0 ? 0 : 1;
}

// What SET_PROGRAM has to accept and what it has to refuse, through the real ioctl.
int run_progcheck(const Args&)
{
	const int fd = open("/dev/" SWDIVERT_DEVICE_NAME, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		die("open /dev/" SWDIVERT_DEVICE_NAME);
	struct Case
	{
		std::string						   what;
		std::vector<swdiv_insn>			   insns;
		std::vector<swdiv_set_desc>		   descs;
		std::vector<std::vector<uint32_t>> arrays;		  // the memory the descriptors point to
		int								   expect_errno;  // 0: accepted
	};
	std::vector<Case> cases;
	auto			  insn = [](uint16_t op, uint16_t src, uint32_t a, uint32_t b, uint16_t fail, uint16_t k = 0) {
		swdiv_insn i = {};
		i.op = op, i.src = src, i.a = a, i.b = b, i.fail = fail, i.k = k;
		return i;
	};
	const swdiv_insn accept = insn(SWDIV_OP_ACCEPT, 0, 0, 0, 0);
	auto			 add	= [&](const std::string& what, std::vector<swdiv_insn> insns, int expect) {
		Case c;
		c.what = what, c.insns = std::move(insns), c.expect_errno = expect;
		cases.push_back(std::move(c));
	};
	auto add_set = [&](Case& c, uint32_t kind, std::vector<uint32_t> elems) {
		c.arrays.push_back(std::move(elems));
		swdiv_set_desc d = {};
		d.kind			 = kind;
		d.n				 = static_cast<__u32>(c.arrays.back().size() / (kind == SWDIV_SET_PORTS ? 2 : 1));
		c.descs.push_back(d);
	};
	add("a plain program", {insn(SWDIV_OP_EQ, SWDIV_SRC_IP_PROTO, 17, 0, 2), accept}, 0);
	add("a program with no instructions", {}, 0);
	add("a jump that does not go forward", {insn(SWDIV_OP_EQ, SWDIV_SRC_IP_PROTO, 17, 0, 0), accept}, EINVAL);
	add("a jump past the end", {insn(SWDIV_OP_EQ, SWDIV_SRC_IP_PROTO, 17, 0, 3), accept}, EINVAL);
	add("an unknown operation", {insn(40, SWDIV_SRC_IP_PROTO, 17, 0, 1)}, EINVAL);
	add("an unknown source", {insn(SWDIV_OP_EQ, 77, 17, 0, 1)}, EINVAL);
	add("a read offset beyond the prefix", {insn(SWDIV_OP_EQ, SWDIV_SRC_RAW_BYTE, 0, 0, 1, 256)}, EINVAL);
	{
		std::vector<swdiv_insn> max(SWDIV_MAX_INSNS, accept);
		add("the largest program (4096 instructions)", max, 0);
		max.push_back(accept);
		add("one instruction too many", max, EINVAL);
	}
	{
		Case c;
		c.what		   = "a set that does not exist";
		c.insns		   = {insn(SWDIV_OP_IN_SET, SWDIV_SRC_IP_SRC, 3, 0, 2), accept};
		c.expect_errno = EINVAL;
		cases.push_back(c);
	}
	{
		Case c;
		c.what		   = "an address set that is used";
		c.insns		   = {insn(SWDIV_OP_IN_SET, SWDIV_SRC_IP_SRC, 0, 0, 2), accept};
		c.expect_errno = 0;
		add_set(c, SWDIV_SET_IPV4, {1, 5, 9});
		cases.push_back(c);
	}
	for (const auto& [what, kind, elems] : std::vector<std::tuple<std::string, uint32_t, std::vector<uint32_t>>>{
			 {"an unsorted address set", SWDIV_SET_IPV4, {5, 1}},
			 {"an address set with a duplicate", SWDIV_SET_IPV4, {5, 5}},
			 {"overlapping port ranges", SWDIV_SET_PORTS, {10, 20, 20, 30}},
			 {"a reversed port range", SWDIV_SET_PORTS, {30, 20}},
			 {"a port beyond 65535", SWDIV_SET_PORTS, {10, 70000}},
			 {"an unknown set kind", 9, {1}}})
	{
		Case c;
		c.what		   = what;
		c.expect_errno = EINVAL;
		add_set(c, kind, elems);
		cases.push_back(std::move(c));
	}
	{
		Case c;
		c.what		   = "the largest set (65536 addresses)";
		c.expect_errno = 0;
		std::vector<uint32_t> big(SWDIV_MAX_SET_ELEMS);
		for (uint32_t i = 0; i < big.size(); ++i)
			big[i] = i;
		add_set(c, SWDIV_SET_IPV4, big);
		cases.push_back(std::move(c));
		Case d;
		d.what		   = "a set one element too large";
		d.expect_errno = EINVAL;
		big.push_back(SWDIV_MAX_SET_ELEMS);
		add_set(d, SWDIV_SET_IPV4, big);
		cases.push_back(std::move(d));
	}
	{
		Case c;
		c.what		   = "64 sets (the limit)";
		c.expect_errno = 0;
		for (uint32_t i = 0; i < SWDIV_MAX_SETS; ++i)
			add_set(c, SWDIV_SET_IPV4, {i});
		cases.push_back(std::move(c));
		Case d;
		d.what		   = "65 sets";
		d.expect_errno = EINVAL;
		for (uint32_t i = 0; i < SWDIV_MAX_SETS + 1; ++i)
			add_set(d, SWDIV_SET_IPV4, {i});
		cases.push_back(std::move(d));
	}
	{
		// 16 sets of 65536 are exactly the total limit of 1 Mi elements; one more is over it
		Case c;
		c.what		   = "sets that add up to exactly the total limit";
		c.expect_errno = 0;
		std::vector<uint32_t> big(SWDIV_MAX_SET_ELEMS);
		for (uint32_t i = 0; i < big.size(); ++i)
			big[i] = i;
		for (int i = 0; i < 16; ++i)
			add_set(c, SWDIV_SET_IPV4, big);
		cases.push_back(c);
		Case d		   = c;
		d.what		   = "sets that add up to more than the total limit";
		d.expect_errno = EINVAL;
		d.descs.clear();
		d.arrays.clear();
		for (int i = 0; i < 17; ++i)
			add_set(d, SWDIV_SET_IPV4, big);
		cases.push_back(std::move(d));
	}

	int failed = 0;
	for (Case& c : cases)
	{
		// The descriptors point into c.arrays (their data pointers are stable: the vectors are not touched again)
		for (size_t i = 0; i < c.descs.size(); ++i)
			c.descs[i].elems = static_cast<__u64>(reinterpret_cast<uintptr_t>(c.arrays[i].data()));
		swdiv_program_args args = {};
		args.insns				= static_cast<__u64>(reinterpret_cast<uintptr_t>(c.insns.data()));
		args.n_insns			= static_cast<__u32>(c.insns.size());
		args.n_sets				= static_cast<__u32>(c.descs.size());
		args.sets				= static_cast<__u64>(reinterpret_cast<uintptr_t>(c.descs.data()));
		errno					= 0;
		const int result		= ioctl(fd, SWDIVERT_IOC_SET_PROGRAM, &args);
		const int got			= result == 0 ? 0 : errno;
		if (got != c.expect_errno)
		{
			std::fprintf(stderr,
						 "progcheck FAIL: %s: expected %s, got %s\n",
						 c.what.c_str(),
						 c.expect_errno ? std::strerror(c.expect_errno) : "success",
						 got ? std::strerror(got) : "success");
			++failed;
		}
	}
	// Bad arguments of the call itself
	auto expect = [&](const char* what, swdiv_program_args args, int expected) {
		errno			 = 0;
		const int result = ioctl(fd, SWDIVERT_IOC_SET_PROGRAM, &args);
		const int got	 = result == 0 ? 0 : errno;
		if (got != expected)
		{
			std::fprintf(stderr,
						 "progcheck FAIL: %s: expected %s, got %s\n",
						 what,
						 expected ? std::strerror(expected) : "success",
						 got ? std::strerror(got) : "success");
			++failed;
		}
	};
	swdiv_program_args a = {};
	a.reserved			 = 1;
	expect("reserved field set", a, EINVAL);
	a		  = {};
	a.n_insns = 5;	// no memory behind the pointer
	expect("instructions at a null pointer", a, EFAULT);
	a.insns = 0x1000;
	expect("instructions at a wild pointer", a, EFAULT);
	a		 = {};
	a.n_sets = 2;
	expect("set descriptors at a null pointer", a, EFAULT);
	a		  = {};
	a.n_insns = 0xFFFFFFFFu;
	expect("an absurd instruction count", a, EINVAL);
	a		 = {};
	a.n_sets = 0xFFFFFFFFu;
	expect("an absurd set count", a, EINVAL);
	std::printf("progcheck_cases=%zu progcheck_failed=%d\n", cases.size() + 6, failed);
	return failed == 0 ? 0 : 1;
}

// ---- fuzzing of the packet-writing ioctls ----
// INJECT and RESUME_MOD take bytes from user space and put them on the wire. This throws well-formed, nearly well-formed and
// plain garbage packets, odd flags, lengths and pointers at them. The module must answer with an error or deliver the packet, and
// neither crash nor hang; the caller then checks that traffic still flows and the kernel log is clean.

int run_fuzz(const Args& args)
{
	const long	   iterations = args.num("--iterations", "20000");
	uint64_t	   rng		  = static_cast<uint64_t>(args.num("--seed", "12345")) * 2862933555777941757ull + 3037000493ull;
	const unsigned ifindex	  = if_nametoindex(args.get("--inject-if", "vc").c_str());
	auto		   next		  = [&]() {
		rng ^= rng << 13;
		rng ^= rng >> 7;
		rng ^= rng << 17;
		return rng;
	};

	const int fd = open("/dev/" SWDIVERT_DEVICE_NAME, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		die("open /dev/" SWDIVERT_DEVICE_NAME);
	swdiv_open_args open_args = {};
	open_args.slots			  = 256;
	open_args.slot_bytes	  = 2048 + SWDIVERT_SLOT_HDR_BYTES;
	open_args.flags			  = SWDIV_OPEN_HOLD;
	if (ioctl(fd, SWDIVERT_IOC_OPEN, &open_args) < 0)
		die("SWDIVERT_IOC_OPEN");
	swdiv_tuple tuple = {};
	tuple.proto		  = IPPROTO_UDP;
	tuple.dport		  = htons(9000);
	ioctl(fd, SWDIVERT_IOC_SET_FILTER, &tuple);
	if (ioctl(fd, SWDIVERT_IOC_START) < 0)
		die("SWDIVERT_IOC_START");

	auto packet = [&]() {
		std::vector<unsigned char> p(static_cast<size_t>(next() % 2200));
		for (auto& byte : p)
			byte = static_cast<unsigned char>(next());
		if (p.size() >= 28 && next() % 10 < 7)
		{
			// A plausible IPv4 packet with a few fields that are wrong
			const size_t ihl					= 5 + next() % 11;
			p[0]								= static_cast<unsigned char>(0x40 | (next() % 8 == 0 ? next() % 16 : ihl));
			const size_t tot					= next() % 6 == 0 ? next() % 4000 : p.size();
			p[2]								= static_cast<unsigned char>(tot >> 8);
			p[3]								= static_cast<unsigned char>(tot);
			static const unsigned char protos[] = {1, 6, 17, 17, 6, 47, 132};
			p[9]								= next() % 8 == 0 ? static_cast<unsigned char>(next()) : protos[next() % 7];
			if (next() % 4 != 0)
				p[6] = p[7] = 0;  // mostly not a fragment
			const unsigned char src[] = {10, 10, 1, 2}, dst[] = {10, 10, 2, 2};
			std::memcpy(&p[12], src, 4);
			if (next() % 3 != 0)
				std::memcpy(&p[16], dst, 4);
		}
		return p;
	};
	auto make_verdict = [](uint64_t id, uint32_t kind) {
		swdiv_verdict v = {};
		v.id			= id;
		v.verdict		= kind;
		return v;
	};
	const uint32_t flag_choices[] = {0, SWDIV_CALC_IP, SWDIV_CALC_L4, SWDIV_CALC_IP | SWDIV_CALC_L4, 0x8, 0xFFFFFFFFu};
	uint64_t	   ok = 0, einval = 0, enoent = 0, other = 0, efault = 0;
	auto		   count = [&](int result) {
		if (result == 0)
			++ok;
		else if (errno == EINVAL)
			++einval;
		else if (errno == ENOENT)
			++enoent;
		else if (errno == EFAULT)
			++efault;
		else
			++other;
	};

	for (long i = 0; i < iterations; ++i)
	{
		std::vector<unsigned char> p = packet();
		switch (next() % 8)
		{
			case 0:
			case 1:
				{
					swdiv_inject_args inject = {};
					inject.data				 = static_cast<__u64>(reinterpret_cast<uintptr_t>(p.data()));
					inject.len				 = static_cast<__u32>(p.size());
					inject.flags			 = flag_choices[next() % 6];
					inject.ifindex			 = ifindex;
					count(ioctl(fd, SWDIVERT_IOC_INJECT, &inject));
					break;
				}
			case 2:
				{
					swdiv_inject_args inject =
						{};	 // odd arguments: a null or wild pointer, an absurd length, an interface that does not exist
					inject.data		= next() % 2 ? 0 : static_cast<__u64>(next());
					inject.len		= next() % 2 ? static_cast<__u32>(next()) : static_cast<__u32>(p.size());
					inject.flags	= flag_choices[next() % 6];
					inject.ifindex	= next() % 2 ? ifindex : static_cast<unsigned>(next() % 100000);
					inject.reserved = next() % 8 == 0;
					count(ioctl(fd, SWDIVERT_IOC_INJECT, &inject));
					break;
				}
			case 3:
			case 4:
				{
					swdiv_verdict verdict	= make_verdict(next() % 64, SWDIV_V_RESUME_MOD);
					verdict.data			= static_cast<__u64>(reinterpret_cast<uintptr_t>(p.data()));
					verdict.len				= static_cast<__u32>(p.size());
					verdict.flags			= flag_choices[next() % 6];
					swdiv_verdict_args args = {};
					args.items				= static_cast<__u64>(reinterpret_cast<uintptr_t>(&verdict));
					args.count				= 1;
					const int result		= ioctl(fd, SWDIVERT_IOC_VERDICT, &args);
					if (result == 0 && verdict.status != 0)
					{
						errno = static_cast<int>(verdict.status);
						count(-1);
					}
					else
					{
						count(result);
					}
					break;
				}
			case 6:
				{
					// A program of random instructions, mostly plausible ones, with sets: the verifier decides
					std::vector<swdiv_insn> insns(next() % 40);
					static const uint16_t	sources[] = {1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 18, 30, 31, 32, 33, 34, 35};
					for (size_t k = 0; k < insns.size(); ++k)
					{
						swdiv_insn& in = insns[k];
						in.op		   = next() % 10 ? static_cast<uint16_t>(1 + next() % 11) : static_cast<uint16_t>(next());
						in.src		   = next() % 6 ? sources[next() % 22] : static_cast<uint16_t>(next());
						in.fail =
							next() % 4 ? static_cast<uint16_t>(k + 1 + next() % (insns.size() - k + 1)) : static_cast<uint16_t>(next());
						in.k = next() % 3 ? 0 : static_cast<uint16_t>(next() % 300);
						in.a = next() % 3 ? static_cast<uint32_t>(next() % 70) : static_cast<uint32_t>(next());
						in.b = next() % 2 ? 0 : static_cast<uint32_t>(next() % 70);
						if (in.op == SWDIV_OP_ACCEPT && next() % 4)
							in.fail = in.src = in.k = 0, in.a = in.b = 0;
					}
					std::vector<std::vector<uint32_t>> arrays(next() % 4);
					std::vector<swdiv_set_desc>		   descs(arrays.size());
					for (size_t k = 0; k < arrays.size(); ++k)
					{
						descs[k].kind  = next() % 8 ? 1 + next() % 2 : static_cast<uint32_t>(next());
						const size_t n = next() % 30;
						arrays[k].resize(n * (descs[k].kind == SWDIV_SET_PORTS ? 2 : 1));
						uint32_t at = static_cast<uint32_t>(next() % 50);
						for (uint32_t& v : arrays[k])
							v = next() % 6 ? (at += 1 + static_cast<uint32_t>(next() % 9)) : static_cast<uint32_t>(next());
						descs[k].n	   = static_cast<__u32>(n);
						descs[k].elems = static_cast<__u64>(reinterpret_cast<uintptr_t>(arrays[k].data()));
					}
					swdiv_program_args pargs = {};
					pargs.insns				 = static_cast<__u64>(reinterpret_cast<uintptr_t>(insns.data()));
					pargs.n_insns			 = static_cast<__u32>(insns.size());
					pargs.n_sets			 = static_cast<__u32>(descs.size());
					pargs.sets				 = static_cast<__u64>(reinterpret_cast<uintptr_t>(descs.data()));
					count(ioctl(fd, SWDIVERT_IOC_SET_PROGRAM, &pargs));
					break;
				}
			case 7:
				{
					// Hostile arguments of the call itself
					swdiv_program_args pargs = {};
					pargs.insns				 = next() % 2 ? 0 : static_cast<__u64>(next());
					pargs.n_insns			 = next() % 2 ? static_cast<__u32>(next() % 6000) : static_cast<__u32>(next());
					pargs.sets				 = next() % 2 ? 0 : static_cast<__u64>(next());
					pargs.n_sets			 = next() % 2 ? static_cast<__u32>(next() % 100) : static_cast<__u32>(next());
					pargs.reserved			 = next() % 8 == 0;
					count(ioctl(fd, SWDIVERT_IOC_SET_PROGRAM, &pargs));
					break;
				}
			default:
				{
					swdiv_verdict verdict	= make_verdict(next(), static_cast<uint32_t>(next() % 6));
					verdict.data			= next() % 2 ? 0 : static_cast<__u64>(next());
					verdict.len				= static_cast<__u32>(next());
					verdict.flags			= static_cast<__u32>(next());
					swdiv_verdict_args args = {};
					args.items	  = next() % 8 ? static_cast<__u64>(reinterpret_cast<uintptr_t>(&verdict)) : static_cast<__u64>(next());
					args.count	  = next() % 8 ? 1 : static_cast<__u32>(next());
					args.reserved = next() % 16 == 0;
					count(ioctl(fd, SWDIVERT_IOC_VERDICT, &args));
					break;
				}
		}
	}
	ioctl(fd, SWDIVERT_IOC_STOP);
	swdiv_stats stats = {};
	ioctl(fd, SWDIVERT_IOC_STATS, &stats);
	std::printf(
		"fuzz_iterations=%ld fuzz_ok=%llu fuzz_einval=%llu fuzz_enoent=%llu fuzz_efault=%llu fuzz_other=%llu injected=%llu "
		"inject_failed=%llu\n",
		iterations,
		static_cast<unsigned long long>(ok),
		static_cast<unsigned long long>(einval),
		static_cast<unsigned long long>(enoent),
		static_cast<unsigned long long>(efault),
		static_cast<unsigned long long>(other),
		static_cast<unsigned long long>(stats.injected),
		static_cast<unsigned long long>(stats.inject_failed));
	return 0;
}

// ---- packet-level checksum verification on the receiving side ----
// A UDP socket cannot tell: veth may mark a received packet as already verified. This looks at the packets as they arrive (AF_PACKET,
// IP level) and checks the IP header checksum and the UDP checksum itself. Packets the stack marks as "checksum not ready yet"
// (offloaded, still the pseudo-header sum) cannot be judged and are counted apart.

uint32_t sum16(const unsigned char* data, size_t size, uint32_t sum)
{
	for (size_t i = 0; i + 1 < size; i += 2)
		sum += (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
	if (size & 1)
		sum += static_cast<uint32_t>(data[size - 1]) << 8;
	return sum;
}

uint16_t fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return static_cast<uint16_t>(sum);
}

int run_pktcheck(const Args& args)
{
	const long		  port	= args.num("--port");
	const std::string iface = args.get("--iface");
	const int		  fd	= socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (fd < 0)
		die("socket AF_PACKET");
	int on = 1;
	setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on));
	int rcvbuf = 16 << 20;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	sockaddr_ll bind_addr  = {};
	bind_addr.sll_family   = AF_PACKET;
	bind_addr.sll_protocol = htons(ETH_P_IP);
	bind_addr.sll_ifindex  = static_cast<int>(if_nametoindex(iface.c_str()));
	if (bind_addr.sll_ifindex == 0 || bind(fd, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0)
		die("bind AF_PACKET");
	install_signals();
	announce_ready();

	uint64_t	  good = 0, bad_ip = 0, bad_l4 = 0, partial = 0, no_l4_sum = 0, total = 0;
	unsigned char buffer[65536];
	while (!g_stop)
	{
		pollfd pfd = {fd, POLLIN, 0};
		if (poll(&pfd, 1, 100) <= 0)
			continue;
		for (;;)
		{
			char		control[256];
			iovec		iov		= {buffer, sizeof(buffer)};
			msghdr		msg		= {};
			sockaddr_ll from	= {};
			msg.msg_name		= &from;
			msg.msg_namelen		= sizeof(from);
			msg.msg_iov			= &iov;
			msg.msg_iovlen		= 1;
			msg.msg_control		= control;
			msg.msg_controllen	= sizeof(control);
			const ssize_t count = recvmsg(fd, &msg, MSG_DONTWAIT);
			if (count <= 0)
				break;
			if (from.sll_pkttype == PACKET_OUTGOING || count < 28)
				continue;
			const size_t ihl = static_cast<size_t>(buffer[0] & 0x0F) * 4;
			if ((buffer[0] >> 4) != 4 || buffer[9] != 17 || ihl + 8 > static_cast<size_t>(count))
				continue;
			const unsigned dport = (static_cast<unsigned>(buffer[ihl + 2]) << 8) | buffer[ihl + 3];
			if (dport != static_cast<unsigned>(port))
				continue;
			++total;
			bool csum_not_ready = false;
			for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c))
				if (c->cmsg_level == SOL_PACKET && c->cmsg_type == PACKET_AUXDATA)
					csum_not_ready = (reinterpret_cast<tpacket_auxdata*>(CMSG_DATA(c))->tp_status & TP_STATUS_CSUMNOTREADY) != 0;
			if (csum_not_ready)
			{
				++partial;
				continue;
			}
			const size_t tot  = (static_cast<size_t>(buffer[2]) << 8) | buffer[3];
			const size_t ulen = tot - ihl;
			bool		 ok	  = true;
			if (fold(sum16(buffer, ihl, 0)) != 0xFFFF)
			{
				++bad_ip;
				ok = false;
			}
			const unsigned udp_sum = (static_cast<unsigned>(buffer[ihl + 6]) << 8) | buffer[ihl + 7];
			if (udp_sum == 0)
			{
				++no_l4_sum;
			}
			else
			{
				uint32_t sum = sum16(buffer + 12, 8, 0) + 17 + static_cast<uint32_t>(ulen);
				sum			 = sum16(buffer + ihl, ulen, sum);
				if (fold(sum) != 0xFFFF)
				{
					++bad_l4;
					ok = false;
				}
			}
			if (ok)
				++good;
		}
	}
	std::printf("pk_total=%llu pk_good=%llu pk_bad_ip=%llu pk_bad_l4=%llu pk_partial=%llu pk_no_l4_sum=%llu\n",
				static_cast<unsigned long long>(total),
				static_cast<unsigned long long>(good),
				static_cast<unsigned long long>(bad_ip),
				static_cast<unsigned long long>(bad_l4),
				static_cast<unsigned long long>(partial),
				static_cast<unsigned long long>(no_l4_sum));
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
	while (recv(fd, drain, sizeof(drain), 0) > 0)
	{
	}
	std::printf("sent=%llu hash=%llu elapsed_ms=%.0f\n",
				static_cast<unsigned long long>(sent),
				static_cast<unsigned long long>(hash),
				static_cast<double>(now_ns() - started) / 1e6);
	return 0;
}

// ---- sniffers ----

struct SniffResult
{
	uint64_t captured = 0;
	uint64_t dropped  = 0;
	uint64_t bytes	  = 0;
	uint64_t polls	  = 0;	// poll() calls that had to wait, i.e. how often the reader went to sleep
	uint64_t wakeups  = 0;	// kernel-side wake_up() calls (swdivert only)
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

swdiv_verdict make_verdict(uint64_t id, uint32_t verdict)
{
	swdiv_verdict v = {};
	v.id			= id;
	v.verdict		= verdict;
	return v;
}

// What the hold modes do to a packet before they resume it
struct ModifyPlan
{
	std::string mode;  // empty: resume unchanged
	uint16_t	to_port = 9001;
	uint32_t	to_ip	= 0;  // network order
};

void put16(std::vector<unsigned char>& p, size_t offset, uint16_t value)
{
	p[offset]	  = static_cast<unsigned char>(value >> 8);
	p[offset + 1] = static_cast<unsigned char>(value & 0xFF);
}

// The new bytes of a UDP packet for the plan (empty: leave it alone, e.g. when the ring only has a truncated copy) and the
// checksum work the kernel has to do for it.
std::vector<unsigned char> build_modified(const unsigned char* pkt, uint32_t len, const ModifyPlan& plan, uint32_t& flags)
{
	std::vector<unsigned char> out;
	if (plan.mode.empty() || len < 28)
		return out;
	const size_t ihl   = static_cast<size_t>(pkt[0] & 0x0F) * 4;
	const size_t total = (static_cast<size_t>(pkt[2]) << 8) | pkt[3];
	if (plan.mode == "tcp-flip")
	{
		// Flips the last byte of every TCP segment that carries data. The receiver only accepts the segment if the checksum the
		// module computed is right, so a transfer that completes proves the TCP checksum code.
		if (pkt[9] != 6 || total > len || ihl + 20 > total)
			return out;
		const size_t header = ihl + static_cast<size_t>(pkt[ihl + 12] >> 4) * 4;
		if (header >= total)
			return out;
		out.assign(pkt, pkt + total);
		out[total - 1] ^= 0xFF;
		flags = SWDIV_CALC_L4;
		return out;
	}
	if (pkt[9] != 17 || ihl + 8 > len || total > len)
		return out;
	out.assign(pkt, pkt + total);
	if (plan.mode == "payload")
	{
		// 'x' -> 'y' behind the 16 bytes of timestamp and sequence number
		for (size_t i = ihl + 8 + 16; i < out.size(); ++i)
			if (out[i] == 'x')
				out[i] = 'y';
		flags = SWDIV_CALC_L4;
	}
	else if (plan.mode == "grow")
	{
		out.insert(out.end(), 100, 'z');
		put16(out, 2, static_cast<uint16_t>(out.size()));
		put16(out, ihl + 4, static_cast<uint16_t>(out.size() - ihl));
		flags = SWDIV_CALC_IP | SWDIV_CALC_L4;
	}
	else if (plan.mode == "shrink")
	{
		if (out.size() > ihl + 8 + 64)
			out.resize(ihl + 8 + 64);
		put16(out, 2, static_cast<uint16_t>(out.size()));
		put16(out, ihl + 4, static_cast<uint16_t>(out.size() - ihl));
		flags = SWDIV_CALC_IP | SWDIV_CALC_L4;
	}
	else if (plan.mode == "dport")
	{
		put16(out, ihl + 2, plan.to_port);
		flags = SWDIV_CALC_L4;
	}
	else if (plan.mode == "dst")
	{
		std::memcpy(&out[16], &plan.to_ip, 4);
		flags = SWDIV_CALC_IP | SWDIV_CALC_L4;
	}
	else if (plan.mode == "bad")
	{
		out[0] = 0x55;	// IP version 5: the module must refuse it and keep the packet held
		flags  = 0;
	}
	return out;
}

// A copy of a packet of flood stream 0-4 as stream 5-9... (stream + 5, so that it is told apart and no copy of a copy is made), to be
// injected
std::vector<unsigned char> build_twin(const unsigned char* pkt, uint32_t len)
{
	std::vector<unsigned char> out;
	if (len < 28)
		return out;
	const size_t ihl   = static_cast<size_t>(pkt[0] & 0x0F) * 4;
	const size_t total = (static_cast<size_t>(pkt[2]) << 8) | pkt[3];
	if (pkt[9] != 17 || total > len || total < ihl + 8 + 16)
		return out;
	uint32_t stream = 0;
	std::memcpy(&stream, pkt + ihl + 8 + 12, sizeof(stream));
	if (stream >= 5)
		return out;
	out.assign(pkt, pkt + total);
	const uint32_t twin = stream + 5;  // a stream of its own per original stream, so twins of different floods never collide
	std::memcpy(&out[ihl + 8 + 12], &twin, sizeof(twin));
	return out;
}

// A verdict batch item waiting for its due time, with the bytes of a RESUME_MOD if there are any
struct Pending
{
	uint64_t				   id;
	uint64_t				   due;
	std::vector<unsigned char> bytes;
	uint32_t				   flags;
};

// Verdicts of the hold modes, sent in batches (one ioctl per drain of the ring)
struct HoldState
{
	int									   fd = -1;
	std::deque<Pending>					   pending;	 // in due order because the delay is constant
	std::vector<swdiv_verdict>			   batch;
	std::deque<std::vector<unsigned char>> batch_data;	// the bytes the RESUME_MOD items of `batch` point to
	uint64_t							   seen = 0, resumed = 0, dropped = 0, enoent = 0, errors = 0, injected = 0, inject_errors = 0;

	void add_resume(uint64_t id, std::vector<unsigned char>&& bytes, uint32_t flags)
	{
		swdiv_verdict v = make_verdict(id, bytes.empty() ? SWDIV_V_RESUME : SWDIV_V_RESUME_MOD);
		if (!bytes.empty())
		{
			batch_data.push_back(std::move(bytes));
			v.data	= static_cast<__u64>(reinterpret_cast<uintptr_t>(batch_data.back().data()));
			v.len	= static_cast<__u32>(batch_data.back().size());
			v.flags = flags;
		}
		batch.push_back(v);
	}
};

void flush_verdicts(HoldState& hold)
{
	size_t offset = 0;
	while (offset < hold.batch.size())
	{
		const size_t	   count = std::min<size_t>(SWDIV_MAX_VERDICTS, hold.batch.size() - offset);
		swdiv_verdict_args args	 = {};
		args.items				 = static_cast<__u64>(reinterpret_cast<uintptr_t>(hold.batch.data() + offset));
		args.count				 = static_cast<__u32>(count);
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
				else if (verdict.status == EINVAL)
					++hold.errors;
				else if (verdict.status == ENOENT)
					++hold.enoent;
				else
					++hold.errors;
			}
		}
		offset += count;
	}
	hold.batch.clear();
	hold.batch_data.clear();
}

// The ring: poll() to sleep, then drain everything that is published. With `hold` the packets are stolen and every one gets a verdict.
int sniff_swdiv(const Args& args, bool hold_mode)
{
	const long delay_ms	  = args.num("--delay-ms", "0");
	const long drop_every = args.num("--drop-every", "0");
	ModifyPlan plan;
	plan.mode	 = args.get("--modify", "");
	plan.to_port = static_cast<uint16_t>(args.num("--to-port", "9001"));
	if (!args.get("--to-ip", "").empty())
		inet_pton(AF_INET, args.get("--to-ip").c_str(), &plan.to_ip);
	const bool	   twin		 = args.get("--twin", "no") != "no";
	const unsigned inject_if = if_nametoindex(args.get("--inject-if", "vc").c_str());
	const long	   port		 = args.num("--port", "0");
	const long	   snap		 = args.num("--snap", "224");
	const long	   slots	 = args.num("--slots", "16384");

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
	open_args.priority		  = static_cast<__s32>(args.num("--prio", "0"));
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
	const std::string filter  = args.get("--filter", "");
	const std::string filter2 = args.get("--filter2", "");
	if (!filter.empty())
	{
		if (!install_filter(fd, filter))
			return 2;
	}
	else
	{
		swdiv_tuple tuple = {};
		tuple.proto		  = args.get("--proto", "udp") == "tcp" ? IPPROTO_TCP : IPPROTO_UDP;
		tuple.dport		  = htons(static_cast<uint16_t>(port));
		if (ioctl(fd, SWDIVERT_IOC_SET_FILTER, &tuple) < 0)
			die("SWDIVERT_IOC_SET_FILTER");
	}
	const long swap_ms = args.num("--swap-ms", "0");
	uint64_t   swap_at = 0;
	bool	   swapped = filter2.empty();

	swdiv_ring_view view;
	swdiv_ring_view_init(&view, data, open_args.hdr_bytes, static_cast<swdiv_cons*>(cons));
	install_signals();
	if (ioctl(fd, SWDIVERT_IOC_START) < 0)
		die("SWDIVERT_IOC_START");
	announce_ready();

	SniffResult result;
	HoldState	hold;
	hold.fd = fd;
	swap_at = now_ns() + static_cast<uint64_t>(swap_ms) * 1000000ull;
	while (!g_stop)
	{
		if (!swapped && now_ns() >= swap_at)
		{
			swapped = true;
			if (!install_filter(fd, filter2))
				std::fprintf(stderr, "swbench: the replacement filter was refused\n");
		}
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
				if (twin && slot->caplen == slot->len)
				{
					std::vector<unsigned char> copy = build_twin(swdiv_slot_data(slot), slot->len);
					if (!copy.empty())
					{
						swdiv_inject_args inject = {};
						inject.data				 = static_cast<__u64>(reinterpret_cast<uintptr_t>(copy.data()));
						inject.len				 = static_cast<__u32>(copy.size());
						inject.flags			 = SWDIV_CALC_IP | SWDIV_CALC_L4;
						inject.ifindex			 = inject_if;
						(ioctl(fd, SWDIVERT_IOC_INJECT, &inject) == 0 ? hold.injected : hold.inject_errors)++;
					}
				}
				uint32_t				   flags = 0;
				std::vector<unsigned char> bytes;
				if (slot->caplen == slot->len)
					bytes = build_modified(swdiv_slot_data(slot), slot->len, plan, flags);
				if (drop_every > 0 && hold.seen % static_cast<uint64_t>(drop_every) == 0)
					hold.batch.push_back(make_verdict(slot->id, SWDIV_V_DROP));
				else if (delay_ms == 0)
					hold.add_resume(slot->id, std::move(bytes), flags);
				else if (delay_ms > 0)
					hold.pending.push_back({slot->id, now + static_cast<uint64_t>(delay_ms) * 1000000ull, std::move(bytes), flags});
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
			while (!hold.pending.empty() && hold.pending.front().due <= now)
			{
				Pending& due = hold.pending.front();
				hold.add_resume(due.id, std::move(due.bytes), due.flags);
				hold.pending.pop_front();
			}
			flush_verdicts(hold);
			if (!hold.pending.empty())
				timeout_ms = static_cast<int>(std::min<uint64_t>(100, (hold.pending.front().due - now) / 1000000ull + 1));
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
		std::printf(
			"held=%llu resumed=%llu vdropped=%llu expired=%llu flushed=%llu dev_dropped=%llu resume_lost=%llu pass_unsupported=%llu "
			"pass_limit=%llu "
			"enoent=%llu verr=%llu modified=%llu mod_dropped=%llu ct_detached=%llu injected=%llu inject_failed=%llu tool_injected=%llu "
			"tool_inject_errors=%llu\n",
			static_cast<unsigned long long>(stats.held),
			static_cast<unsigned long long>(stats.resumed),
			static_cast<unsigned long long>(stats.verdict_dropped),
			static_cast<unsigned long long>(stats.expired),
			static_cast<unsigned long long>(stats.flushed),
			static_cast<unsigned long long>(stats.dev_dropped),
			static_cast<unsigned long long>(stats.resume_lost),
			static_cast<unsigned long long>(stats.pass_unsupported),
			static_cast<unsigned long long>(stats.pass_limit),
			static_cast<unsigned long long>(hold.enoent),
			static_cast<unsigned long long>(hold.errors),
			static_cast<unsigned long long>(stats.modified),
			static_cast<unsigned long long>(stats.mod_dropped),
			static_cast<unsigned long long>(stats.ct_detached),
			static_cast<unsigned long long>(stats.injected),
			static_cast<unsigned long long>(stats.inject_failed),
			static_cast<unsigned long long>(hold.injected),
			static_cast<unsigned long long>(hold.inject_errors));
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

// What the kernel does for SWDIV_CALC_*, done in user space: NFQUEUE hands back exactly the bytes it is given, so this is what an
// NFQUEUE-based engine has to do for every packet it changes (lagsw does it with calc_checksums()).
void calc_checksums_user(std::vector<unsigned char>& p, uint32_t flags)
{
	const size_t ihl  = static_cast<size_t>(p[0] & 0x0F) * 4;
	const size_t ulen = p.size() - ihl;
	if ((flags & SWDIV_CALC_L4) && p[9] == 17 && ulen >= 8)
	{
		p[ihl + 6] = p[ihl + 7] = 0;
		uint32_t sum			= sum16(p.data() + 12, 8, 0) + 17 + static_cast<uint32_t>(ulen);
		sum						= sum16(p.data() + ihl, ulen, sum);
		uint16_t csum			= static_cast<uint16_t>(~fold(sum));
		if (csum == 0)
			csum = 0xFFFF;
		p[ihl + 6] = static_cast<unsigned char>(csum >> 8);
		p[ihl + 7] = static_cast<unsigned char>(csum);
	}
	if (flags & SWDIV_CALC_IP)
	{
		p[10] = p[11]		= 0;
		const uint16_t csum = static_cast<uint16_t>(~fold(sum16(p.data(), ihl, 0)));
		p[10]				= static_cast<unsigned char>(csum >> 8);
		p[11]				= static_cast<unsigned char>(csum);
	}
}

struct NfqState
{
	ModifyPlan								  plan;
	SniffResult								  result;
	bool									  hold		 = false;
	long									  delay_ms	 = 0;
	long									  drop_every = 0;
	bool									  batch		 = false;  // one verdict for all packets of a receive, as the shipped backend does
	bool									  batch_open = false;
	uint32_t								  batch_last = 0;
	uint64_t								  seen		 = 0;
	std::deque<std::pair<uint32_t, uint64_t>> pending;	// (packet id, due time in ns)
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
	if (state->hold && !state->plan.mode.empty() && length > 0)
	{
		uint32_t				   flags = 0;
		std::vector<unsigned char> bytes = build_modified(payload, static_cast<uint32_t>(length), state->plan, flags);
		if (!bytes.empty())
		{
			calc_checksums_user(bytes, flags | SWDIV_CALC_IP);	// an NFQUEUE engine recomputes both, whatever it changed
			return nfq_set_verdict(queue, id, NF_ACCEPT, static_cast<uint32_t>(bytes.size()), bytes.data());
		}
	}
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
			return 0;  // never: the kernel drops it when the listener goes away
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
	NfqState state;
	state.hold			= hold_mode;
	state.delay_ms		= args.num("--delay-ms", "0");
	state.drop_every	= args.num("--drop-every", "0");
	state.batch			= args.get("--batch", "no") != "no";
	state.plan.mode		= args.get("--modify", "");
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
	if (command == "pktcheck")
		return run_pktcheck(args);
	if (command == "fuzz")
		return run_fuzz(args);
	if (command == "vmcheck")
		return run_vmcheck(args);
	if (command == "progcheck")
		return run_progcheck(args);
	if (command == "backend")
		return run_backend(args.v);
	if (command == "backend-load")
		return run_backend_load(args.v);
	if (command == "backend-api")
		return run_backend_api(args.v);
	if (command == "tcpsink")
		return run_tcpsink(args);
	if (command == "tcpsend")
		return run_tcpsend(args);
	usage();
}
