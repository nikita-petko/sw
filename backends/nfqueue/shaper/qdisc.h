#ifndef NFQUEUE_SHAPER_QDISC_H_
#define NFQUEUE_SHAPER_QDISC_H_

#include <cstdint>
#include <string>

/// The few rtnetlink operations the egress tier needs on a network interface: look up the root qdisc, replace it with `fq`
/// (the qdisc that honours the departure times the eBPF program sets) and put the previous kind back.
namespace nfq::qdisc {

struct FqParameters
{
	uint32_t packet_limit	   = 262144;  ///< Packets queued in total; delay x packet rate must fit.
	uint32_t flow_packet_limit = 65536;	  ///< Packets queued per flow.
	uint32_t horizon_ms		   = 900000;  ///< Furthest departure time accepted; beyond it a time is capped, not dropped.
};

struct Interface
{
	uint32_t index = 0;
	/// Length of the link-layer header the egress program must skip: 14 for Ethernet, 0 for devices without one.
	uint32_t l2_len = 0;
};

/// Resolves an interface name. Fails for names that do not exist or link types the program cannot parse.
bool resolve_interface(const std::string& name, Interface& out, std::string& error);

/// Kind of the root qdisc ("noqueue", "pfifo_fast", "fq_codel", "mq", "fq", ...).
bool root_kind(uint32_t ifindex, std::string& kind, std::string& error);

/// Root qdisc kinds that can be replaced and later restored without losing configuration the operator is likely to care about.
bool replaceable_kind(const std::string& kind);

/// Replaces the root qdisc with fq. Existing queued packets of the old qdisc are dropped by the kernel.
bool install_fq(uint32_t ifindex, const FqParameters& parameters, std::string& error);

/// Puts a root qdisc of `kind` back, with its default parameters ("noqueue" removes the root qdisc).
bool restore(uint32_t ifindex, const std::string& kind, std::string& error);

/// Packets currently queued in the root qdisc.
bool queued_packets(uint32_t ifindex, uint32_t& packets, std::string& error);

}  // namespace nfq::qdisc

#endif
