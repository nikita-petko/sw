#include "verdict_tracker.h"

#include <unordered_set>

namespace nfq {
namespace {
constexpr uint32_t kHalfRange = 0x80000000u;
}

void VerdictTracker::add(uint32_t id, uint32_t mark)
{
	uint64_t epoch = epoch_;
	// The kernel numbers packets in arrival order, so a much smaller id means the counter wrapped, and a much larger
	// one is a straggler from before the wrap.
	if (!seen_any_)
		last_id_ = id;
	else if (id < last_id_ && last_id_ - id > kHalfRange)
	{
		epoch	 = ++epoch_;
		last_id_ = id;
	}
	else if (id > last_id_ && id - last_id_ > kHalfRange && epoch_ > 0)
		epoch = epoch_ - 1;
	else if (id > last_id_)
		last_id_ = id;
	seen_any_ = true;

	const uint64_t widened = (epoch << 32) | id;
	const auto	   known   = widened_.find(id);
	if (known != widened_.end())
		waiting_.erase(known->second);
	waiting_[widened] = mark;
	widened_[id]	  = widened;
}

bool VerdictTracker::remove(uint32_t id)
{
	const auto known = widened_.find(id);
	if (known == widened_.end())
		return false;
	waiting_.erase(known->second);
	widened_.erase(known);
	return true;
}

VerdictTracker::Run VerdictTracker::plan(const std::vector<uint32_t>& ids) const
{
	Run result;
	if (ids.size() < 2 || waiting_.empty())
		return result;
	std::unordered_set<uint64_t> released;
	released.reserve(ids.size());
	for (const uint32_t id : ids)
	{
		const auto known = widened_.find(id);
		if (known != widened_.end())
			released.insert(known->second);
	}
	const uint32_t first_mark = waiting_.begin()->second;
	for (const auto& [widened, mark] : waiting_)
	{
		if (released.count(widened) == 0 || mark != first_mark)
			break;
		result.ids.push_back(static_cast<uint32_t>(widened));
	}
	// A single packet gains nothing from a batch verdict.
	if (result.ids.size() < 2)
	{
		result.ids.clear();
		return result;
	}
	result.last_id = result.ids.back();
	result.mark	   = first_mark;
	return result;
}

}  // namespace nfq
