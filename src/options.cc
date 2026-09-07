#include "options.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "log.h"
#include "windivert_runtime.h"

namespace {
constexpr const char* kDefaultFilter = "tcp.DstPort == 55000 or tcp.SrcPort == 55000";
constexpr int		  kTabKey		 = 0x09;

std::string trim(std::string value)
{
	const auto first = value.find_first_not_of(" \t\r\n");
	if (first == std::string::npos)
		return {};
	const auto last = value.find_last_not_of(" \t\r\n");
	return value.substr(first, last - first + 1);
}

std::optional<bool> parse_bool(const std::string& value)
{
	if (value == "true")
		return true;
	if (value == "false")
		return false;
	return std::nullopt;
}

std::optional<ProfileActivationMode> parse_activation_mode(const std::string& value)
{
	if (value == "toggle")
		return ProfileActivationMode::toggle;
	if (value == "hold")
		return ProfileActivationMode::hold;
	return std::nullopt;
}

std::optional<ProfileKeyMode> parse_key_mode(const std::string& value)
{
	if (value == "oneof")
		return ProfileKeyMode::oneof;
	if (value == "combination")
		return ProfileKeyMode::combination;
	return std::nullopt;
}

std::optional<WinDivertOptions::ServerDirection> parse_server_direction(const std::string& value)
{
	if (value == "source")
		return WinDivertOptions::ServerDirection::source;
	if (value == "destination")
		return WinDivertOptions::ServerDirection::destination;
	if (value == "both")
		return WinDivertOptions::ServerDirection::both;
	return std::nullopt;
}

logging::level parse_log_level(const std::string& value)
{
	if (value == "error")
		return logging::level::error;
	if (value == "warn")
		return logging::level::warn;
	if (value == "info")
		return logging::level::info;
	if (value == "debug")
		return logging::level::debug;

	return logging::level::info;
}

std::string unquote(std::string value)
{
	if (value.size() >= 2 && ((value.front() == '\'' && value.back() == '\'') || (value.front() == '"' && value.back() == '"')))
		return value.substr(1, value.size() - 2);
	return value;
}

std::optional<int> parse_key(std::string value)
{
	value = unquote(trim(value));
	if (value.size() == 1)
		return static_cast<unsigned char>(std::toupper(static_cast<unsigned char>(value[0])));
	if (value == "tab" || value == "VK_TAB")
		return kTabKey;
	if (value == "space" || value == "VK_SPACE")
		return 0x20;
	if (value == "alt" || value == "menu" || value == "VK_MENU")
		return 0x12;
	if (value == "ctrl" || value == "control" || value == "VK_CONTROL")
		return 0x11;
	if (value == "shift" || value == "VK_SHIFT")
		return 0x10;
	try
	{
		size_t	  consumed = 0;
		const int key	   = std::stoi(value, &consumed, 0);
		return consumed == value.size() ? std::optional<int>(key) : std::nullopt;
	}
	catch (...)
	{
		return std::nullopt;
	}
}

std::optional<PacketDelayMode> parse_delay_mode(const std::string& value)
{
	if (value == "from_timestamp")
		return PacketDelayMode::from_timestamp;
	if (value == "send_all_after_delay")
		return PacketDelayMode::send_all_after_delay;
	if (value == "ratio")
		return PacketDelayMode::ratio;
	if (value == "drop")
		return PacketDelayMode::drop;
	if (value == "drop_and_send")
		return PacketDelayMode::drop_and_send;
	if (value == "drop_until_toggle")
		return PacketDelayMode::drop_until_toggle;
	return std::nullopt;
}

std::optional<RetransmissionMode> parse_retransmission_mode(const std::string& value)
{
	if (value == "none")
		return RetransmissionMode::none;
	if (value == "only_seq")
		return RetransmissionMode::only_seq;
	if (value == "only_ack")
		return RetransmissionMode::only_ack;
	if (value == "both")
		return RetransmissionMode::both;
	return std::nullopt;
}

bool add_keys(const std::string& value, ProfileOptions& profile, const char* path, int line_number)
{
	std::string list = trim(value);
	if (list.size() >= 2 && list.front() == '[' && list.back() == ']')
		list = list.substr(1, list.size() - 2);
	else if (list.empty())
		return true;
	else
		list += ',';
	for (size_t start = 0; start < list.size();)
	{
		const size_t	  end  = list.find(',', start);
		const std::string item = trim(list.substr(start, end == std::string::npos ? std::string::npos : end - start));
		const auto		  key  = parse_key(item);
		if (!key)
		{
			LOG_ERROR("Invalid profile key in %s at line %d", path, line_number);
			return false;
		}
		if (*key == kTabKey)
		{
			LOG_ERROR("Tab is reserved for printing packet engine state in %s at line %d", path, line_number);
			return false;
		}
		profile.keys.push_back(*key);
		if (end == std::string::npos)
			break;
		start = end + 1;
	}
	return true;
}

bool add_disabled_profiles(const std::string& value, ProfileOptions& profile, const char* path, int line_number)
{
	std::string list = trim(value);
	if (list.size() >= 2 && list.front() == '[' && list.back() == ']')
		list = list.substr(1, list.size() - 2);
	else if (list.empty())
		return true;
	else
		list += ',';
	for (size_t start = 0; start < list.size();)
	{
		const size_t	  end  = list.find(',', start);
		const std::string item = unquote(trim(list.substr(start, end == std::string::npos ? std::string::npos : end - start)));
		if (item.empty())
		{
			LOG_ERROR("Invalid disabled profile in %s at line %d", path, line_number);
			return false;
		}
		profile.disables.push_back(item);
		if (end == std::string::npos)
			break;
		start = end + 1;
	}
	return true;
}

bool add_server(const std::string& value, PacketEngineOptions& options, const char* path, int line_number)
{
	const std::string item = unquote(trim(value));
	if (item.empty())
	{
		LOG_ERROR("Invalid empty server in %s at line %d", path, line_number);
		return false;
	}
	const size_t  separator = item.find(':');
	ServerOptions server;
	server.address = trim(item.substr(0, separator));
	server.name	   = separator == std::string::npos ? server.address : trim(item.substr(separator + 1));
	if (server.address.empty() || server.name.empty())
	{
		LOG_ERROR("Invalid server '%s' in %s at line %d; expected address or address:name", item.c_str(), path, line_number);
		return false;
	}
	if (std::find_if(options.servers.begin(), options.servers.end(), [&](const ServerOptions& existing) {
			return existing.address == server.address;
		}) != options.servers.end())
		return true;
	options.servers.push_back(server);
	return true;
}

bool load_profiles(const char* path, PacketEngineOptions& options)
{
	std::ifstream file(path);
	if (!file)
	{
		LOG_ERROR("Unable to open profiles file: %s", path);
		return false;
	}

	options.profiles.clear();
	options.servers.clear();
	std::string		line;
	ProfileOptions* profile = nullptr;
	std::string		section;
	std::string		subsection;
	int				subsection_indent = -1;
	int				line_number		  = 0;
	while (std::getline(file, line))
	{
		++line_number;
		const int  indent  = static_cast<int>(line.find_first_not_of(" \t"));
		const auto comment = line.find('#');
		if (comment != std::string::npos)
			line.erase(comment);
		const std::string content = trim(line);
		if (content.empty())
			continue;
		if (subsection == "keys" && content.front() == '-' && content.find(':') == std::string::npos)
		{
			if (!profile || indent <= subsection_indent || !add_keys(content.substr(1), *profile, path, line_number))
				return false;
			continue;
		}
		if (subsection == "disables" && content.front() == '-' && content.find(':') == std::string::npos)
		{
			if (!profile || indent <= subsection_indent || !add_disabled_profiles(content.substr(1), *profile, path, line_number))
				return false;
			continue;
		}
		if (subsection == "servers" && content.front() == '-')
		{
			if (indent <= subsection_indent || !add_server(content.substr(1), options, path, line_number))
				return false;
			continue;
		}
		const auto colon = content.find(':');
		if (colon == std::string::npos)
		{
			LOG_ERROR("Invalid YAML in %s at line %d", path, line_number);
			return false;
		}
		std::string key	  = trim(content.substr(0, colon));
		std::string value = trim(content.substr(colon + 1));
		if (key == "- name")
		{
			options.profiles.push_back({});
			profile		  = &options.profiles.back();
			profile->name = unquote(value);
			subsection.clear();
			subsection_indent = -1;
			continue;
		}
		if (key == "profiles" && value.empty())
		{
			section = "profiles";
			subsection.clear();
			subsection_indent = -1;
			continue;
		}
		if (key == "servers" && value.empty())
		{
			subsection		  = "servers";
			subsection_indent = indent;
			continue;
		}
		if (indent == 0 && key == "servers")
		{
			std::string list = trim(value);
			if (list.size() < 2 || list.front() != '[' || list.back() != ']')
			{
				LOG_ERROR("Invalid servers list in %s at line %d", path, line_number);
				return false;
			}
			list = list.substr(1, list.size() - 2);
			for (size_t start = 0; start < list.size();)
			{
				const size_t end = list.find(',', start);
				if (!add_server(list.substr(start, end == std::string::npos ? std::string::npos : end - start), options, path, line_number))
					return false;
				if (end == std::string::npos)
					break;
				start = end + 1;
			}
			subsection.clear();
			subsection_indent = -1;
			continue;
		}
		if (key == "windivert_options" && value.empty() && profile)
		{
			subsection		  = "windivert_options";
			subsection_indent = indent;
			continue;
		}
		if (key == "keys" && profile)
		{
			subsection		  = "keys";
			subsection_indent = indent;
			if (!add_keys(value, *profile, path, line_number))
				return false;
			continue;
		}
		if (key == "disables" && profile)
		{
			subsection		  = "disables";
			subsection_indent = indent;
			if (!add_disabled_profiles(value, *profile, path, line_number))
				return false;
			continue;
		}
		if (key == "key" && profile)
		{
			subsection.clear();
			subsection_indent = -1;
			if (!add_keys(value, *profile, path, line_number))
				return false;
			continue;
		}
		if (indent == 0 && key == "global_filter")
		{
			options.global_filter = unquote(value);
			continue;
		}
		if (!profile || section != "profiles")
			continue;
		if (subsection == "windivert_options" && indent > subsection_indent)
		{
			if (key == "server_direction")
			{
				const auto direction = parse_server_direction(unquote(value));
				if (!direction)
				{
					LOG_ERROR("Invalid server_direction in %s at line %d: expected source, destination, or both", path, line_number);
					return false;
				}
				profile->windivert_options.server_direction = *direction;
				continue;
			}
			const auto parsed = parse_bool(value);
			if (!parsed)
			{
				LOG_ERROR("Invalid boolean in %s at line %d", path, line_number);
				return false;
			}
			if (key == "sniff")
				profile->windivert_options.sniff = *parsed;
			else if (key == "forward")
				profile->windivert_options.forward = *parsed;
			else if (key == "outbound")
				profile->windivert_options.outbound = *parsed;
			else
			{
				subsection.clear();
				subsection_indent = -1;
			}
			continue;
		}
		subsection.clear();
		subsection_indent = -1;
		if (key == "name")
			profile->name = unquote(value);
		else if (key == "key_mode")
		{
			const auto mode = parse_key_mode(unquote(value));
			if (!mode)
			{
				LOG_ERROR("Invalid profile key_mode in %s at line %d: expected oneof or combination", path, line_number);
				return false;
			}
			profile->key_mode = *mode;
		}
		else if (key == "mode")
		{
			const auto mode = parse_activation_mode(unquote(value));
			if (!mode)
			{
				LOG_ERROR("Invalid profile mode in %s at line %d: expected toggle or hold", path, line_number);
				return false;
			}
			profile->mode = *mode;
		}
		else if (key == "delay_mode")
		{
			const auto mode = parse_delay_mode(unquote(value));
			if (!mode)
			{
				LOG_ERROR(
					"Invalid delay_mode in %s at line %d: expected from_timestamp, send_all_after_delay, ratio, drop, drop_and_send, or "
					"drop_until_toggle",
					path,
					line_number);
				return false;
			}
			profile->delay_mode = *mode;
		}
		else if (key == "retransmission_mode")
		{
			const auto mode = parse_retransmission_mode(unquote(value));
			if (!mode)
			{
				LOG_ERROR("Invalid retransmission_mode in %s at line %d: expected none, only_seq, only_ack, or both", path, line_number);
				return false;
			}
			profile->retransmission_mode = *mode;
		}
		else if (key == "delay_ms")
		{
			try
			{
				profile->delay_ms = static_cast<int32_t>(std::stol(value));
			}
			catch (...)
			{
				LOG_ERROR("Invalid delay_ms in %s at line %d", path, line_number);
				return false;
			}
		}
		else if (key == "ratio")
		{
			std::string ratio_value = trim(unquote(value));
			const bool	percent		= !ratio_value.empty() && ratio_value.back() == '%';
			if (percent)
				ratio_value.pop_back();
			try
			{
				size_t consumed = 0;
				profile->ratio	= static_cast<int32_t>(std::stol(ratio_value, &consumed));
				if (consumed != ratio_value.size())
					throw std::invalid_argument("trailing characters");
				profile->ratio_percent	  = percent;
				profile->ratio_configured = true;
			}
			catch (...)
			{
				LOG_ERROR("Invalid ratio in %s at line %d", path, line_number);
				return false;
			}
		}
		else if (key == "filter")
			profile->filter = unquote(value);
	}
	for (const ProfileOptions& item : options.profiles)
	{
		if (item.name.empty() || item.keys.empty())
		{
			LOG_ERROR("Each profile in %s requires a name and key(s)", path);
			return false;
		}
		if ((item.delay_mode == PacketDelayMode::ratio || item.delay_mode == PacketDelayMode::drop_and_send) &&
			(item.ratio <= 0 || (item.ratio_percent && item.ratio > 100) || item.delay_ms <= 0))
		{
			LOG_ERROR("Profile '%s' requires a positive ratio and delay_ms", item.name.c_str());
			return false;
		}
		if (item.delay_mode == PacketDelayMode::drop_and_send && !item.ratio_configured)
		{
			LOG_ERROR("Profile '%s' requires ratio to be configured", item.name.c_str());
			return false;
		}
		if (item.delay_mode == PacketDelayMode::drop_until_toggle && item.mode != ProfileActivationMode::toggle)
		{
			LOG_ERROR("Profile '%s' requires toggle mode for drop_until_toggle", item.name.c_str());
			return false;
		}
		for (const std::string& disabled_name : item.disables)
		{
			if (disabled_name == "*")
				continue;
			if (disabled_name == item.name)
			{
				LOG_ERROR("Profile '%s' cannot disable itself", item.name.c_str());
				return false;
			}
			const auto target = std::find_if(options.profiles.begin(), options.profiles.end(), [&](const ProfileOptions& candidate) {
				return candidate.name == disabled_name;
			});
			if (target == options.profiles.end())
			{
				LOG_ERROR("Profile '%s' disables unknown profile '%s'", item.name.c_str(), disabled_name.c_str());
				return false;
			}
		}
	}
	if (options.profiles.empty())
	{
		LOG_ERROR("No profiles found in %s", path);
		return false;
	}

	return true;
}

bool validate_filters(const char* path, const PacketEngineOptions& options)
{
	if (options.profiles.empty())
	{
		LOG_ERROR("A profiles YAML file must contain at least one profile: %s", path);
		return false;
	}
	for (const ProfileOptions& profile : options.profiles)
	{
		LOG_DEBUG("Validating filter '%s' for profile '%s'", profile.filter.value_or(options.global_filter).c_str(), profile.name.c_str());

		const bool		   outbound = profile.windivert_options.outbound.value_or(false);
		const bool		   forward	= profile.windivert_options.forward.value_or(false);
		const std::string& filter	= profile.filter.value_or(options.global_filter);
		if (outbound && forward)
		{
			LOG_ERROR("Invalid options for profile '%s': outbound requires forward to be false", profile.name.c_str());
			return false;
		}
		for (size_t server_index = 0; server_index <= options.servers.size(); ++server_index)
		{
			std::string server_filter = filter;
			if (server_index != 0 && profile.windivert_options.server_direction)
			{
				const char* address_field = "ip.Addr";
				switch (*profile.windivert_options.server_direction)
				{
					case WinDivertOptions::ServerDirection::source:
						address_field = "ip.SrcAddr";
						break;
					case WinDivertOptions::ServerDirection::destination:
						address_field = "ip.DstAddr";
						break;
					case WinDivertOptions::ServerDirection::both:
						break;
				}
				server_filter = "(" + server_filter + ") and " + address_field + " == " + options.servers[server_index - 1].address;
			}
			const std::string capture_filter = outbound ? "outbound and (" + server_filter + ")" : server_filter;
			const char*		  error			 = nullptr;
			UINT			  error_position = 0;
			if (!WinDivertHelperCompileFilter(capture_filter.c_str(),
											  forward ? WINDIVERT_LAYER_NETWORK_FORWARD : WINDIVERT_LAYER_NETWORK,
											  nullptr,
											  0,
											  &error,
											  &error_position))
			{
				LOG_ERROR("Invalid filter for profile '%s' in %s at position %u: %s",
						  profile.name.c_str(),
						  path,
						  error_position,
						  error ? error : "unknown error");
				return false;
			}
		}
	}
	return true;
}
}  // namespace

bool parse_options(int argc, char* argv[], PacketEngineOptions& options)
{
	options.global_filter = kDefaultFilter;
	options.profiles.clear();
	options.initial_server.reset();
	options.discovery_port.reset();
	options.discovery_window_ms = 5000;
	bool config_loaded			= false;
	for (int index = 1; index < argc; ++index)
	{
		if (std::strcmp(argv[index], "--config") == 0)
		{
			if (index + 1 >= argc)
			{
				LOG_ERROR("--config requires a profiles YAML file");
				return false;
			}
			config_loaded = true;
			if (!load_profiles(argv[++index], options))
				return false;
		}
		else if (std::strcmp(argv[index], "--log-level") == 0 || std::strcmp(argv[index], "-l") == 0)
		{
			if (index + 1 >= argc)
			{
				LOG_ERROR("--log-level requires error, warn, info, or debug");
				return false;
			}

			const logging::level requested_level = parse_log_level(argv[++index]);
#ifdef NDEBUG
			if (requested_level == logging::level::debug)
			{
				logging::set_level(logging::level::info);
				LOG_WARN("Debug logging is not supported on release builds; clamping log level to info");
			}
			else
#endif
				logging::set_level(requested_level);
		}
		else if (std::strcmp(argv[index], "--server") == 0 || std::strcmp(argv[index], "-s") == 0)
		{
			if (index + 1 >= argc)
			{
				LOG_ERROR("--server requires a configured server name or address");
				return false;
			}
			options.initial_server = argv[++index];
		}
		else if (std::strcmp(argv[index], "--discover") == 0 || std::strcmp(argv[index], "--discover-port") == 0)
		{
			if (index + 1 >= argc)
			{
				LOG_ERROR("%s requires a port from 1 to 65535", argv[index]);
				return false;
			}
			try
			{
				size_t				consumed = 0;
				const unsigned long port	 = std::stoul(argv[++index], &consumed);
				if (consumed != std::strlen(argv[index]) || port == 0 || port > (std::numeric_limits<uint16_t>::max)())
					throw std::invalid_argument("invalid port");
				options.discovery_port = static_cast<uint16_t>(port);
			}
			catch (...)
			{
				LOG_ERROR("Invalid discovery port: %s", argv[index]);
				return false;
			}
		}
		else if (std::strcmp(argv[index], "--discover-window") == 0)
		{
			if (index + 1 >= argc)
			{
				LOG_ERROR("--discover-window requires a positive duration in milliseconds");
				return false;
			}
			try
			{
				size_t					 consumed = 0;
				const unsigned long long window	  = std::stoull(argv[++index], &consumed);
				if (consumed != std::strlen(argv[index]) || window == 0)
					throw std::invalid_argument("invalid window");
				options.discovery_window_ms = window;
			}
			catch (...)
			{
				LOG_ERROR("Invalid discovery window: %s", argv[index]);
				return false;
			}
		}
		else if (std::strcmp(argv[index], "--help") == 0 || std::strcmp(argv[index], "-h") == 0 || argc == 1)
		{
			std::printf("Usage: %s [options]\nOptions:\n", argv[0]);
			std::printf("  --config <file> Load profiles from YAML\n");
			std::printf("  --log-level, -l <level> Set log level: error, warn, info, or debug\n");
			std::printf("  --server, -s <server> Select the initial configured server\n");
			std::printf("  --discover <port>      Discover the busiest server on a TCP/UDP port\n");
			std::printf("  --discover-window <ms> Discovery window (default: 5000)\n");
			std::printf("  --help, -h              Show this help message\n");
			return false;
		}
	}
	if (!config_loaded)
	{
		LOG_ERROR("--config is required");
		return false;
	}
	return validate_filters("command line", options);
}