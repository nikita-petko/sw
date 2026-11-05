#ifndef KMOD_PAYLOAD_HASH_H_
#define KMOD_PAYLOAD_HASH_H_

#include <cstdint>
#include <cstring>

namespace kmodb {

/// Fingerprint of a packet's bytes. recv() takes it before the engine sees the packet and send() takes it again, so an unchanged packet is
/// resumed as it is (the kernel keeps its offload and checksum state) and only a changed one is sent back as new bytes. It detects
/// edits, it is not a defence against anybody: the engine is the only party that can change the bytes.
///
/// It runs twice per packet, so it has to be fast: a byte-at-a-time FNV-1a took 384 ns for the 228-byte packets of the benchmark
/// (its multiply chain is one byte per ~4 cycles), about 0.8 us per packet for the two calls, which was the whole gap between the
/// backend and the raw reader in the Phase 6 benchmark. Four independent lanes of 8 bytes each step make this about 20x faster.
/// A change to any 8-byte word changes the state of its lane for certain (each step is a bijection of the word), so one edit is
/// always seen; several edits could only cancel by cancelling across lanes after the final mixing.
inline uint64_t hash_payload(const uint8_t* data, uint32_t length)
{
	constexpr uint64_t kMul1 = 0x9E3779B97F4A7C15ull;
	constexpr uint64_t kMul2 = 0xC2B2AE3D27D4EB4Full;
	constexpr uint64_t kMul3 = 0x165667B19E3779F9ull;
	constexpr uint64_t kMul4 = 0x27D4EB2F165667C5ull;
	auto			   step	 = [](uint64_t lane, uint64_t word, uint64_t multiplier) {
		lane = (lane ^ word) * multiplier;
		return (lane << 31) | (lane >> 33);
	};
	auto load = [](const uint8_t* at) {
		uint64_t word;
		std::memcpy(&word, at, sizeof(word));
		return word;
	};

	uint64_t	   a = 0x243F6A8885A308D3ull ^ length, b = 0x13198A2E03707344ull, c = 0xA4093822299F31D0ull, d = 0x082EFA98EC4E6C89ull;
	const uint8_t* p	= data;
	uint32_t	   left = length;
	for (; left >= 32; left -= 32, p += 32)
	{
		a = step(a, load(p), kMul1);
		b = step(b, load(p + 8), kMul2);
		c = step(c, load(p + 16), kMul3);
		d = step(d, load(p + 24), kMul4);
	}
	for (; left >= 8; left -= 8, p += 8)
		a = step(a, load(p), kMul1);
	if (left != 0)
	{
		uint64_t tail = 0;
		std::memcpy(&tail, p, left);
		b = step(b, tail, kMul2);
	}

	uint64_t result = a + (b * kMul3) + (c * kMul4) + (d * kMul1);
	result ^= result >> 29;
	result *= kMul2;
	result ^= result >> 32;
	return result;
}

}  // namespace kmodb

#endif
