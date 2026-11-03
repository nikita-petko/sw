#ifndef NFQUEUE_VERDICT_TRACKER_H_
#define NFQUEUE_VERDICT_TRACKER_H_

#include <cstddef>
#include <cstdint>
#include <map>
#include <unordered_map>
#include <vector>

namespace nfq {

/// Packets that were handed to user space and still wait for a verdict, in the order the kernel queued them.
///
/// A batch verdict (NFQNL_MSG_VERDICT_BATCH) applies to *every* packet of the queue up to a packet id, so it may only
/// be used when no other packet at or below that id is still held for a different decision. plan() finds the longest
/// run of the oldest waiting packets that a release covers completely. Not thread-safe; the caller serialises access.
class VerdictTracker
{
public:
	/// The oldest waiting packets that one batch verdict can release.
	struct Run
	{
		uint32_t			  last_id = 0;	///< Packet id to put in the batch verdict.
		uint32_t			  mark	  = 0;	///< Netfilter mark shared by every packet of the run.
		std::vector<uint32_t> ids;			///< Ids released by the run, oldest first; empty unless at least two packets qualify.
	};

	/// Registers a queued packet. Ids are assigned in increasing order and wrap at 2^32.
	void add(uint32_t id, uint32_t mark);

	/// Forgets a packet that received its verdict. Returns false when it was not waiting.
	bool remove(uint32_t id);

	/// Number of packets waiting for a verdict.
	std::size_t size() const { return waiting_.size(); }

	/// Longest leading run of waiting packets that are all in `ids`. A verdict batch carries a single mark, so the run
	/// also stops at the first packet whose mark differs from the oldest one's.
	Run plan(const std::vector<uint32_t>& ids) const;

private:
	// Ids are widened to 64 bits so ordering survives the 32-bit wraparound.
	std::map<uint64_t, uint32_t>		   waiting_;  ///< widened id -> mark
	std::unordered_map<uint32_t, uint64_t> widened_;  ///< id -> widened id
	uint64_t							   epoch_	 = 0;
	uint32_t							   last_id_	 = 0;
	bool								   seen_any_ = false;
};

}  // namespace nfq

#endif
