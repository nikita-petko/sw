#include "options.h"

#include <cstdio>
#include <cstring>
#include <string>

#include "internal.h"
#include "log.h"

namespace {
constexpr const char* kDefaultFilter = "tcp.DstPort == 55000 or tcp.SrcPort == 55000";

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
}  // namespace

bool parse_options(int argc, char* argv[], PacketEngineOptions& options)
{
	options.global_filter = kDefaultFilter;
	options.profiles.clear();
	options.initial_server.reset();
	options.client_source_address.reset();
	options.client_destination_address.reset();
	options.resolve_region = false;
	options.features	   = {};
	bool config_loaded	   = false;

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
			if (!config::load_profiles(argv[++index], options))
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
		else if (std::strcmp(argv[index], "--client-address") == 0 || std::strcmp(argv[index], "--client-source-address") == 0 ||
				 std::strcmp(argv[index], "--client-destination-address") == 0)
		{
			if (index + 1 >= argc)
			{
				LOG_ERROR("%s requires an IPv4 or IPv6 address", argv[index]);
				return false;
			}
			const std::string address = argv[++index];
			if (std::strcmp(argv[index - 1], "--client-destination-address") == 0)
				options.client_destination_address = address;
			else if (std::strcmp(argv[index - 1], "--client-source-address") == 0)
				options.client_source_address = address;
			else
			{
				options.client_source_address	   = address;
				options.client_destination_address = address;
			}
		}
		else if (std::strcmp(argv[index], "--resolve-region") == 0)
		{
			options.resolve_region = true;
		}
		else if (std::strcmp(argv[index], "--help") == 0 || std::strcmp(argv[index], "-h") == 0 || argc == 1)
		{
			std::printf("Usage: %s [options]\nOptions:\n", argv[0]);
			std::printf("  --config <file> Load profiles from YAML\n");
			std::printf("  --log-level, -l <level> Set log level: error, warn, info, or debug\n");
			std::printf("  --server, -s <server> Select the initial configured server\n");
			std::printf("  --client-address <address> Set both client source and destination addresses\n");
			std::printf("  --client-source-address <address> Set the client source address\n");
			std::printf("  --client-destination-address <address> Set the client destination address\n");
			std::printf("  --resolve-region        Resolve the geographic region of discovered servers\n");
			std::printf("  --help, -h              Show this help message\n");
			return false;
		}
	}
	if (!config_loaded)
	{
		LOG_ERROR("--config is required");
		return false;
	}
	return config::validate_filters("command line", options);
}
