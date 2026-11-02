#ifndef NFQUEUE_SHAPER_SHAPER_H_
#define NFQUEUE_SHAPER_SHAPER_H_

#include <memory>
#include <string>

#include "packet_backend.h"

/// Kernel shaping for the Linux backend: an eBPF program on the egress of the configured interfaces stamps packets with a
/// departure time that the `fq` qdisc honours (or drops them), so delayed packets never visit user space. Two
/// implementations exist, chosen at build time: shaper_bpf.cc (libbpf) and shaper_none.cc (`--linux_tier=nfqueue`).
namespace nfq::shaper {

void configure(const backend::ShapingConfig& config);

/// Opens a stage, or returns nullptr with the reason the stage must use an NFQUEUE channel.
std::unique_ptr<backend::ShapeStage> open_stage(const backend::ShapeSpec& spec, std::string& reason);

/// Counters for the status line, or an empty string when no stage was ever opened.
std::string status_text();

}  // namespace nfq::shaper

#endif
