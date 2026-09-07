#include "packet_mode.h"

namespace {
class DropMode final : public PacketMode
{
public:
	explicit DropMode(ProfileOptions options) : PacketMode(std::move(options), "drop") {}

	void capture(const BYTE*, UINT, const WINDIVERT_ADDRESS&, int, uint64_t, uint64_t, PacketQueue&) override {}
	void release(PacketQueue&, uint64_t, std::vector<PacketNode*>&) override {}
	void flush(PacketQueue&, std::vector<PacketNode*>&) override {}
};
}

std::unique_ptr<PacketMode> create_drop_mode(const ProfileOptions& options)
{
	return std::make_unique<DropMode>(options);
}
