#ifndef NFQUEUE_MONITOR_H_
#define NFQUEUE_MONITOR_H_

#include <cstdint>
#include <string>

namespace nfq {

/// Samples /proc/net/netfilter/nfnetlink_queue for the queues `first_queue` .. `first_queue + queue_count - 1` and checks
/// that the nftables table is still installed, then returns a one-line summary. The sample is reused until `interval_ms`
/// has elapsed, so the (process-spawning) table check stays cheap when called often. Not thread-safe.
std::string monitor_status(uint16_t first_queue, uint32_t queue_count, uint64_t interval_ms, uint32_t backlog_threshold);

}  // namespace nfq

#endif
