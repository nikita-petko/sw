// Built when the eBPF tier is left out (`xmake f --linux_tier=nfqueue`, or no clang/libbpf at build time).
#include "shaper.h"

namespace nfq::shaper {

void configure(const backend::ShapingConfig&)
{
}

std::unique_ptr<backend::ShapeStage> open_stage(const backend::ShapeSpec&, std::string& reason)
{
	reason = "this build does not include the eBPF tier";
	return nullptr;
}

std::string status_text()
{
	return {};
}

}  // namespace nfq::shaper
