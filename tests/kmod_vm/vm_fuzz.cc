// Fuzz harness of the swdivert filter VM (Phase 5 of pocs/linux_kernel_module_backend.md). It runs the header the kernel includes
// (kmod/include/swdivert_vm.h) under AddressSanitizer and UndefinedBehaviorSanitizer on random programs, mutated real programs, random sets
// and hostile packets. Every buffer the VM may read is its own heap allocation of exactly the right size, so a read one byte too far is
// an ASan report, and every instruction the interpreter executes is counted, so a program that runs longer than it has instructions is a
// failure. Usage: kmod_vm_fuzz [iterations] [seed]
#include <cstdio>
#include <cstdlib>
#include <memory>

static unsigned long long g_steps = 0;
#define SWDIV_VM_STEP() (++g_steps)

#include "support.h"

using namespace vmtest;

namespace {

[[noreturn]] void fail(const char* what)
{
	std::fprintf(stderr, "kmod_vm_fuzz: FAILED: %s\n", what);
	std::abort();
}

// A heap block of exactly `n` elements, so that ASan sees any access beyond it
template<typename T>
struct Exact
{
	std::unique_ptr<T[]> data;
	size_t				 size = 0;
	Exact()					  = default;
	explicit Exact(size_t n) : data(new T[n ? n : 1]()), size(n) {}
	T* get() const { return data.get(); }
};

Exact<uint8_t> exact_bytes(const Bytes& bytes)
{
	Exact<uint8_t> block(bytes.size());
	std::copy(bytes.begin(), bytes.end(), block.get());
	return block;
}

uint32_t pick_src(Rng& rng)
{
	static const uint16_t valid[] = {SWDIV_SRC_IP_PROTO,
									 SWDIV_SRC_IP_SRC,
									 SWDIV_SRC_IP_DST,
									 SWDIV_SRC_IP_TTL,
									 SWDIV_SRC_IP_TOTLEN,
									 SWDIV_SRC_IP_FRAG,
									 SWDIV_SRC_RAW_BYTE,
									 SWDIV_SRC_TCP_SPORT,
									 SWDIV_SRC_TCP_DPORT,
									 SWDIV_SRC_UDP_SPORT,
									 SWDIV_SRC_UDP_DPORT,
									 SWDIV_SRC_TCP_FLAGS,
									 SWDIV_SRC_TCP_PAYLOAD_BYTE,
									 SWDIV_SRC_UDP_PAYLOAD_BYTE,
									 SWDIV_SRC_TCP_PAYLOAD_LEN,
									 SWDIV_SRC_UDP_PAYLOAD_LEN,
									 SWDIV_SRC_IN_IFINDEX,
									 SWDIV_SRC_OUT_IFINDEX,
									 SWDIV_SRC_MARK,
									 SWDIV_SRC_OUTBOUND,
									 SWDIV_SRC_LOOPBACK,
									 SWDIV_SRC_PKT_LEN};
	return rng.chance(85) ? valid[rng.below(sizeof(valid) / sizeof(valid[0]))] : static_cast<uint32_t>(rng.next());
}

uint32_t special(Rng& rng)
{
	static const uint32_t values[] = {0, 1, 2, 6, 17, 80, 255, 256, 9000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF};
	return rng.chance(60) ? values[rng.below(14)] : static_cast<uint32_t>(rng.next());
}

struct RandomSets
{
	std::vector<Exact<uint32_t>> blocks;
	std::vector<swdiv_vm_set>	 views;
};

RandomSets random_sets(Rng& rng)
{
	RandomSets	   sets;
	const unsigned count = rng.below(5);
	for (unsigned i = 0; i < count; ++i)
	{
		const uint32_t	kind = rng.chance(90) ? 1 + rng.below(2) : static_cast<uint32_t>(rng.next());
		const uint32_t	n	 = rng.chance(10) ? 0 : rng.below(40);
		const uint32_t	per	 = kind == SWDIV_SET_PORTS ? 2 : 1;
		Exact<uint32_t> block(static_cast<size_t>(n) * per);
		for (size_t j = 0; j < block.size; ++j)
			block.get()[j] = special(rng);
		if (rng.chance(75))
		{
			// Make it a valid set most of the time
			if (per == 1)
			{
				const uint32_t base = rng.below(5);
				for (size_t j = 0; j < block.size; ++j)
					block.get()[j] = static_cast<uint32_t>(j) * 3 + base;  // strictly ascending
			}
			else
			{
				uint32_t at = rng.below(100);
				for (uint32_t j = 0; j < n; ++j)
				{
					block.get()[2 * j]	   = at;
					block.get()[2 * j + 1] = at + rng.below(50);
					at					   = block.get()[2 * j + 1] + 1 + rng.below(100);
				}
			}
		}
		sets.views.push_back({kind, n, block.get()});
		sets.blocks.push_back(std::move(block));
	}
	return sets;
}

std::vector<swdiv_insn> random_program(Rng& rng)
{
	const uint32_t			n = rng.chance(5) ? 0 : rng.below(50);
	std::vector<swdiv_insn> insns(n);
	for (uint32_t i = 0; i < n; ++i)
	{
		swdiv_insn& insn = insns[i];
		insn.op			 = rng.chance(10) ? static_cast<uint16_t>(rng.next())
										  : static_cast<uint16_t>(rng.chance(12) ? SWDIV_OP_ACCEPT : 2 + rng.below(10));
		insn.src		 = static_cast<uint16_t>(pick_src(rng));
		insn.fail		 = rng.chance(75) ? static_cast<uint16_t>(i + 1 + rng.below(n - i + 1)) : static_cast<uint16_t>(rng.next());
		insn.k			 = rng.chance(70) ? 0 : static_cast<uint16_t>(rng.chance(80) ? rng.below(300) : rng.next());
		insn.a			 = special(rng);
		insn.b			 = rng.chance(50) ? 0 : special(rng);
		if (insn.op == SWDIV_OP_ACCEPT && rng.chance(80))
			insn.fail = insn.src = insn.k = 0, insn.a = insn.b = 0;
		if ((insn.op == SWDIV_OP_IN_SET || insn.op == SWDIV_OP_NOT_IN_SET) && rng.chance(70))
			insn.a = rng.below(5), insn.b = 0;
	}
	return insns;
}

Bytes hostile_packet(Rng& rng)
{
	switch (rng.below(6))
	{
		case 0:
			return Bytes();
		case 1:
			return Bytes(rng.below(20), static_cast<uint8_t>(rng.next()));	// too short for an IP header
		case 2:
			{
				Bytes b(rng.below(400));
				for (uint8_t& byte : b)
					byte = static_cast<uint8_t>(rng.next());
				if (!b.empty() && rng.chance(60))
					b[0] = static_cast<uint8_t>(0x40 | rng.below(16));	// IPv4 with any header length
				return b;
			}
		default:
			return random_packet(rng);
	}
}

unsigned long long g_runs = 0, g_matches = 0, g_verified = 0, g_programs = 0, g_max_steps = 0;

void run_on_packets(Rng& rng, const std::vector<swdiv_insn>& program, const RandomSets& sets, bool verified, unsigned packets)
{
	const uint32_t	  n = static_cast<uint32_t>(program.size());
	Exact<swdiv_insn> insns(n);
	std::copy(program.begin(), program.end(), insns.get());
	for (unsigned i = 0; i < packets; ++i)
	{
		const Bytes			 packet = hostile_packet(rng);
		const Exact<uint8_t> block	= exact_bytes(packet);
		swdiv_vm_ctx		 ctx	= {};
		ctx.pkt						= block.get();
		ctx.len						= static_cast<uint32_t>(std::min<size_t>(packet.size(), SWDIV_VM_PREFIX));
		ctx.total_len				= static_cast<uint32_t>(packet.size());
		ctx.in_ifindex				= rng.below(5);
		ctx.out_ifindex				= rng.below(5);
		ctx.mark					= static_cast<uint32_t>(rng.next());
		ctx.outbound				= 1;
		if (rng.chance(3))
			ctx.len = static_cast<uint32_t>(packet.size());	 // an oversized prefix is refused, not read
		g_steps			 = 0;
		const int result = swdiv_vm_run(insns.get(), n, sets.views.data(), static_cast<uint32_t>(sets.views.size()), &ctx);
		if (result != 0 && result != 1)
			fail("the VM returned something other than 0 or 1");
		// Every executed instruction moves forward, so a program never executes more steps than it has instructions
		if (g_steps > n)
			fail("the VM executed more instructions than the program has");
		if (verified && g_steps > SWDIV_MAX_INSNS)
			fail("a verified program ran longer than the limit");
		g_max_steps = std::max<unsigned long long>(g_max_steps, g_steps);
		++g_runs;
		g_matches += static_cast<unsigned long long>(result);
	}
}

void fuzz_programs(Rng& rng)
{
	const std::vector<swdiv_insn> program = random_program(rng);
	RandomSets					  sets	  = random_sets(rng);
	bool						  sets_ok = true;
	for (const swdiv_vm_set& set : sets.views)
		if (swdiv_vm_verify_set(set.kind, set.n, set.elems) != 0)
			sets_ok = false;
	const bool verified = sets_ok && swdiv_vm_verify(program.data(),
													 static_cast<uint32_t>(program.size()),
													 sets.views.data(),
													 static_cast<uint32_t>(sets.views.size())) == 0;
	++g_programs;
	g_verified += verified;
	// Verified programs are the contract; unverified ones must not be able to hurt either (the interpreter does not trust the verifier)
	run_on_packets(rng, program, sets, verified, verified ? 12 : 3);
}

void fuzz_mutated_real_programs(Rng& rng)
{
	kmodf::Program compiled;
	std::string	   error;
	uint32_t	   position = 0;
	for (int attempt = 0; attempt < 20; ++attempt)
		if (kmodf::compile_program(random_filter(rng, 1 + rng.below(4)), compiled, error, position) && !compiled.insns.empty())
			break;
	if (compiled.insns.empty())
		return;
	std::vector<swdiv_insn> mutated = compiled.insns;
	const unsigned			edits	= 1 + rng.below(3);
	for (unsigned e = 0; e < edits; ++e)
	{
		swdiv_insn& insn = mutated[rng.below(static_cast<uint32_t>(mutated.size()))];
		switch (rng.below(6))
		{
			case 0:
				insn.op = static_cast<uint16_t>(rng.chance(50) ? 1 + rng.below(12) : rng.next());
				break;
			case 1:
				insn.src = static_cast<uint16_t>(pick_src(rng));
				break;
			case 2:
				insn.fail = static_cast<uint16_t>(rng.chance(50) ? rng.below(static_cast<uint32_t>(mutated.size() + 2)) : rng.next());
				break;
			case 3:
				insn.a = special(rng);
				break;
			case 4:
				insn.b = special(rng);
				break;
			default:
				insn.k = static_cast<uint16_t>(rng.below(300));
				break;
		}
	}
	// The sets of the real program, as exact blocks
	RandomSets sets;
	bool	   sets_ok = true;
	for (const kmodf::SetData& set : compiled.sets)
	{
		Exact<uint32_t> block(set.elems.size());
		std::copy(set.elems.begin(), set.elems.end(), block.get());
		const uint32_t per = set.kind == SWDIV_SET_PORTS ? 2 : 1;
		sets.views.push_back({set.kind, static_cast<uint32_t>(set.elems.size() / per), block.get()});
		sets.blocks.push_back(std::move(block));
		if (swdiv_vm_verify_set(set.kind, static_cast<uint32_t>(set.elems.size() / per), set.elems.data()) != 0)
			sets_ok = false;
	}
	if (!sets_ok)
		fail("the compiler produced a set the verifier refuses");
	const bool verified = swdiv_vm_verify(mutated.data(),
										  static_cast<uint32_t>(mutated.size()),
										  sets.views.data(),
										  static_cast<uint32_t>(sets.views.size())) == 0;
	++g_programs;
	g_verified += verified;
	run_on_packets(rng, mutated, sets, verified, 12);
}

// The set search against a linear scan, for valid sets of both kinds
void fuzz_set_search(Rng& rng)
{
	const bool			  ports = rng.chance(50);
	Exact<uint32_t>		  block(0);
	uint32_t			  n = rng.below(60);
	std::vector<uint32_t> elems;
	if (!ports)
	{
		for (uint32_t i = 0; i < n; ++i)
			elems.push_back(special(rng) % 500);
		std::sort(elems.begin(), elems.end());
		elems.erase(std::unique(elems.begin(), elems.end()), elems.end());
		n = static_cast<uint32_t>(elems.size());
	}
	else
	{
		uint32_t at = rng.below(50);
		for (uint32_t i = 0; i < n; ++i)
		{
			const uint32_t hi = at + rng.below(30);
			elems.push_back(at);
			elems.push_back(hi);
			at = hi + 1 + rng.below(40);
		}
	}
	block = Exact<uint32_t>(elems.size());
	std::copy(elems.begin(), elems.end(), block.get());
	const swdiv_vm_set set{static_cast<uint32_t>(ports ? SWDIV_SET_PORTS : SWDIV_SET_IPV4), n, block.get()};
	if (swdiv_vm_verify_set(set.kind, n, set.elems) != 0)
		fail("a set built to be valid was refused");
	for (uint32_t v = 0; v < 520; v += 1)
	{
		bool expected = false;
		if (!ports)
			expected = std::binary_search(elems.begin(), elems.end(), v);
		else
			for (uint32_t i = 0; i < n; ++i)
				expected |= v >= elems[2 * i] && v <= elems[2 * i + 1];
		if (swdiv_vm_in_set(&set, v) != (expected ? 1 : 0))
			fail("the set search disagrees with a linear scan");
	}
}

}  // namespace

int main(int argc, char** argv)
{
	const unsigned long long iterations = argc > 1 ? std::strtoull(argv[1], nullptr, 0) : 20000;
	const unsigned long long seed		= argc > 2 ? std::strtoull(argv[2], nullptr, 0) : 1;
	Rng						 rng(seed);
	for (unsigned long long i = 0; i < iterations; ++i)
	{
		switch (rng.below(10))
		{
			case 0:
				fuzz_set_search(rng);
				break;
			case 1:
			case 2:
			case 3:
				fuzz_mutated_real_programs(rng);
				break;
			default:
				fuzz_programs(rng);
				break;
		}
	}
	std::printf(
		"kmod_vm_fuzz: %llu iterations (seed %llu), %llu programs of which %llu verified, %llu runs, %llu matches, at most %llu steps: no "
		"report\n",
		iterations,
		seed,
		g_programs,
		g_verified,
		g_runs,
		g_matches,
		g_max_steps);
	return 0;
}
