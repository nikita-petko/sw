#include "packet_mode.h"

#include <stdexcept>

std::unique_ptr<PacketMode> create_from_timestamp_mode(const ProfileOptions& options);
std::unique_ptr<PacketMode> create_send_all_after_delay_mode(const ProfileOptions& options);
std::unique_ptr<PacketMode> create_ratio_mode(const ProfileOptions& options);
std::unique_ptr<PacketMode> create_drop_mode(const ProfileOptions& options);
std::unique_ptr<PacketMode> create_drop_and_send_mode(const ProfileOptions& options);
std::unique_ptr<PacketMode> create_drop_until_toggle_mode(const ProfileOptions& options);

std::unique_ptr<PacketMode> create_packet_mode(const ProfileOptions& options)
{
	switch (options.delay_mode)
	{
		case PacketDelayMode::from_timestamp:
			return create_from_timestamp_mode(options);
		case PacketDelayMode::send_all_after_delay:
			return create_send_all_after_delay_mode(options);
		case PacketDelayMode::ratio:
			return create_ratio_mode(options);
		case PacketDelayMode::drop:
			return create_drop_mode(options);
		case PacketDelayMode::drop_and_send:
			return create_drop_and_send_mode(options);
		case PacketDelayMode::drop_until_toggle:
			return create_drop_until_toggle_mode(options);
	}
	throw std::logic_error("unsupported packet delay mode");
}
