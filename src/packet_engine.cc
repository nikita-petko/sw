#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif
#ifndef WINVER
#	define WINVER 0x0A00
#endif
#ifndef _WIN32_WINNT
#	define _WIN32_WINNT 0x0A00
#endif

#include "packet_engine.h"
#include <windows.h>

#include <mmsystem.h>
#include <winhttp.h>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include "modules/packet_mode.h"
#include "windivert_runtime.h"

#include "log.h"

namespace {
std::string format_win32_error(DWORD error)
{
	char* message = nullptr;
	const DWORD length = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
										 nullptr,
										 error,
										 0,
										 reinterpret_cast<char*>(&message),
										 0,
										 nullptr);
	if (length == 0)
		return "unknown error";
	std::string result(message, length);
	LocalFree(message);
	while (!result.empty() && (result.back() == '\r' || result.back() == '\n'))
		result.pop_back();
	return result;
}

const char* key_name(int key)
{
	if (key == 0x20)
		return "space";
	if (key == 0x12)
		return "alt";
	if (key == 0x11)
		return "ctrl";
	if (key == 0x10)
		return "shift";
	return nullptr;
}

std::string format_keys(const ProfileOptions& profile)
{
	std::string result;
	const char* separator = profile.key_mode == ProfileKeyMode::oneof ? " or " : "+";
	for (const int key : profile.keys)
	{
		if (!result.empty())
			result += separator;
		if (const char* name = key_name(key))
			result += name;
		else if (key >= 0x20 && key <= 0x7E)
			result += static_cast<char>(key);
		else
			result += std::to_string(key);
	}
	return result;
}

std::string format_state_divider(size_t width, const std::string& label = {})
{
	const size_t inner_width = width - 2;
	if (label.empty())
		return "|" + std::string(inner_width, '-') + "|";

	const std::string text		 = " " + label + " ";
	const size_t	  left_width = (inner_width - text.size()) / 2;
	return "|" + std::string(left_width, '-') + text + std::string(inner_width - left_width - text.size(), '-') + "|";
}

// bright white, contrasts with the green LOG_INFO text around it
constexpr const char* kStatColor = "\033[97m";
// switches back to the green LOG_INFO color after a highlighted stat
constexpr const char* kStatReset = "\033[32m";

std::string highlight(const std::string& value)
{
	return std::string(kStatColor) + value + kStatReset;
}

size_t visible_length(const std::string& text)
{
	size_t length = 0;
	for (size_t index = 0; index < text.size(); ++index)
	{
		if (text[index] == '\033' && index + 1 < text.size() && text[index + 1] == '[')
		{
			index += 2;
			while (index < text.size() && text[index] != 'm')
				++index;
			continue;
		}
		++length;
	}
	return length;
}

void log_state_line(size_t width, const std::string& text)
{
	const size_t inner_width = width - 4;
	const size_t visible	 = visible_length(text);
	const size_t padding	 = visible < inner_width ? inner_width - visible : 0;
	LOG_INFO("| %s%*s |", text.c_str(), static_cast<int>(padding), "");
}

std::string format_ipv4_address(UINT32 address)
{
	const auto* bytes	   = reinterpret_cast<const unsigned char*>(&address);
	char		buffer[16] = {};
	std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
	return buffer;
}

std::string format_ipv6_address(const UINT32* address)
{
	const auto* bytes	   = reinterpret_cast<const unsigned char*>(address);
	char		buffer[64] = {};
	std::snprintf(buffer,
				  sizeof(buffer),
				  "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
				  bytes[0],
				  bytes[1],
				  bytes[2],
				  bytes[3],
				  bytes[4],
				  bytes[5],
				  bytes[6],
				  bytes[7],
				  bytes[8],
				  bytes[9],
				  bytes[10],
				  bytes[11],
				  bytes[12],
				  bytes[13],
				  bytes[14],
				  bytes[15]);
	return buffer;
}

struct PacketAddresses
{
	std::string source;
	std::string destination;
};

PacketAddresses packet_addresses(const BYTE* packet_data, UINT packet_length)
{
	PWINDIVERT_IPHDR ip_header = nullptr;
	PWINDIVERT_IPV6HDR ipv6_header = nullptr;
	if (!WinDivertHelperParsePacket(packet_data,
									packet_length,
									&ip_header,
									&ipv6_header,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr,
									nullptr))
		return {};

	if (ip_header != nullptr)
		return {format_ipv4_address(ip_header->SrcAddr), format_ipv4_address(ip_header->DstAddr)};
	if (ipv6_header != nullptr)
		return {format_ipv6_address(ipv6_header->SrcAddr), format_ipv6_address(ipv6_header->DstAddr)};
	return {};
}

// avoids wasted lookups for local/test infrastructure that has no meaningful geographic region
bool is_public_address(const std::string& address)
{
	if (address.empty())
		return false;
	if (address.rfind("10.", 0) == 0 || address.rfind("127.", 0) == 0 || address.rfind("192.168.", 0) == 0 ||
		address.rfind("169.254.", 0) == 0 || address == "::1" || address.rfind("fe80:", 0) == 0 || address.rfind("fc", 0) == 0 ||
		address.rfind("fd", 0) == 0)
		return false;
	if (address.rfind("172.", 0) == 0)
	{
		const size_t next_dot = address.find('.', 4);
		if (next_dot != std::string::npos)
		{
			try
			{
				const int second_octet = std::stoi(address.substr(4, next_dot - 4));
				if (second_octet >= 16 && second_octet <= 31)
					return false;
			}
			catch (...)
			{
			}
		}
	}
	return true;
}

std::optional<std::string> extract_json_string(const std::string& json, const std::string& key)
{
	const std::string needle = "\"" + key + "\":";
	auto			  start	 = json.find(needle);
	if (start == std::string::npos)
		return std::nullopt;
	start += needle.size();
	while (start < json.size() && (json[start] == ' ' || json[start] == '\t'))
		++start;
	if (start >= json.size() || json[start] != '"')
		return std::nullopt;
	const auto value_start = start + 1;
	const auto value_end = json.find('"', value_start);
	if (value_end == std::string::npos)
		return std::nullopt;
	return json.substr(value_start, value_end - value_start);
}

std::optional<double> extract_json_number(const std::string& json, const std::string& key)
{
	const std::string needle = "\"" + key + "\":";
	auto			  start	 = json.find(needle);
	if (start == std::string::npos)
		return std::nullopt;
	start += needle.size();
	while (start < json.size() && (json[start] == ' ' || json[start] == '\t'))
		++start;
	size_t end = start;
	while (end < json.size() && (std::isdigit(static_cast<unsigned char>(json[end])) || json[end] == '-' || json[end] == '+' || json[end] == '.'))
		++end;
	if (end == start)
		return std::nullopt;
	try
	{
		return std::stod(json.substr(start, end - start));
	}
	catch (...)
	{
		return std::nullopt;
	}
}

std::string last_ip_segment(const std::string& address)
{
	const size_t dot = address.find_last_of('.');
	if (dot != std::string::npos)
		return address.substr(dot + 1);
	const size_t colon = address.find_last_of(':');
	if (colon != std::string::npos)
		return address.substr(colon + 1);
	return address;
}

// coarse west/central/east split per region group, since ipapi.co has no notion of "US-West" vs "US-East" etc.
std::string country_region_code(const std::optional<std::string>& country_code,
								 const std::optional<std::string>& continent_code,
								 const std::optional<double>&		longitude)
{
	struct LongitudeBand
	{
		double west_max;
		double east_min;
	};
	static const std::unordered_map<std::string, LongitudeBand> longitude_bands = {
		{"US", {-115.0, -90.0}},
		{"CA", {-115.0, -90.0}},
		{"NA", {-115.0, -90.0}},
		{"EU", {-5.0, 25.0}},
		{"AS", {70.0, 120.0}},
		{"OC", {130.0, 150.0}},
		{"SA", {-70.0, -50.0}},
		{"AF", {10.0, 30.0}},
	};
	const std::string	 group	   = country_code && *country_code == "US" ? "US" : continent_code.value_or(country_code.value_or("XX"));
	const auto			 band_it   = longitude_bands.find(group);
	const LongitudeBand	 band	   = band_it == longitude_bands.end() ? LongitudeBand{-30.0, 30.0} : band_it->second;
	const double		 lon	   = longitude.value_or(0.0);
	const char			 suffix	   = lon < band.west_max ? 'W' : lon > band.east_min ? 'E' : 'C';
	return group + suffix;
}

// e.g. "IA-USC-19" for region_code IA, country_region USC, and address ending in .19
std::string build_server_name(const std::string& address, const std::string& response)
{
	const auto region_code	   = extract_json_string(response, "region_code");
	const auto country_code   = extract_json_string(response, "country_code");
	const auto continent_code = extract_json_string(response, "continent_code");
	const auto longitude	   = extract_json_number(response, "longitude");
	return region_code.value_or("XX") + "-" + country_region_code(country_code, continent_code, longitude) + "-" + last_ip_segment(address);
}

std::optional<std::string> extract_region_label(const std::string& response)
{
	const auto region  = extract_json_string(response, "region");
	const auto country = extract_json_string(response, "country_name");
	if (!region && !country)
		return std::nullopt;
	std::string label = region.value_or("");
	if (region && country)
		label += ", ";
	label += country.value_or("");
	return label;
}

struct RegionCacheEntry
{
	std::string label;
	std::string server_name;
	uint64_t expires_at = 0;
};

constexpr uint64_t region_cache_lifetime_seconds = 30 * 24 * 60 * 60;
const char* client_region_cache_key = "@client";

std::string region_cache_path()
{
	const char* local_app_data = std::getenv("LOCALAPPDATA");
	if (!local_app_data || *local_app_data == '\0')
		return {};
	return std::string(local_app_data) + "\\lagsw\\region-cache.csv";
}

std::string csv_field(const std::string& value)
{
	if (value.find_first_of(",\"\r\n") == std::string::npos)
		return value;
	std::string escaped = "\"";
	for (const char character : value)
	{
		if (character == '"')
			escaped += '"';
		escaped += character;
	}
	escaped += '"';
	return escaped;
}

std::optional<std::vector<std::string>> parse_csv_line(const std::string& line)
{
	std::vector<std::string> fields;
	std::string field;
	bool quoted = false;
	for (size_t index = 0; index < line.size(); ++index)
	{
		const char character = line[index];
		if (quoted)
		{
			if (character == '"' && index + 1 < line.size() && line[index + 1] == '"')
				field += line[++index];
			else if (character == '"')
				quoted = false;
			else
				field += character;
		}
		else if (character == '"' && field.empty())
			quoted = true;
		else if (character == ',')
		{
			fields.push_back(field);
			field.clear();
		}
		else
			field += character;
	}
	if (quoted)
		return std::nullopt;
	fields.push_back(field);
	return fields;
}

void load_region_cache(std::unordered_map<std::string, RegionCacheEntry>& cache)
{
	const std::string path = region_cache_path();
	if (path.empty())
		return;
	std::ifstream file(path);
	bool legacy_tsv = false;
	if (!file)
	{
		const std::string legacy_path = path.substr(0, path.size() - 4) + ".tsv";
		file.open(legacy_path);
		legacy_tsv = true;
	}
	const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
	std::string line;
	while (std::getline(file, line))
	{
		std::optional<std::vector<std::string>> fields;
		if (legacy_tsv)
		{
			fields = std::vector<std::string>();
			size_t start = 0;
			while (true)
			{
				const size_t separator = line.find('\t', start);
				fields->push_back(line.substr(start, separator == std::string::npos ? std::string::npos : separator - start));
				if (separator == std::string::npos)
					break;
				start = separator + 1;
			}
		}
		else
			fields = parse_csv_line(line);
		if (!fields || fields->size() != 4)
			continue;
		try
		{
			const uint64_t expiry = std::stoull((*fields)[3]);
			if (!(*fields)[0].empty() && expiry > now)
				cache[(*fields)[0]] = {(*fields)[1], (*fields)[2], expiry};
		}
		catch (const std::exception&)
		{
			LOG_DEBUG("Ignoring malformed region cache entry");
		}
	}
}

void save_region_cache(const std::unordered_map<std::string, RegionCacheEntry>& cache)
{
	const std::string path = region_cache_path();
	if (path.empty())
		return;
	const std::string directory = path.substr(0, path.find_last_of("\\/"));
	CreateDirectoryA(directory.c_str(), nullptr);
	const std::string temporary_path = path + ".tmp";
	std::ofstream file(temporary_path, std::ios::trunc);
	if (!file)
		return;
	for (const auto& [address, entry] : cache)
		file << csv_field(address) << ',' << csv_field(entry.label) << ',' << csv_field(entry.server_name) << ',' << entry.expires_at << '\n';
	file.close();
	if (!MoveFileExA(temporary_path.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		DeleteFileA(temporary_path.c_str());
}

struct HttpResponse
{
	DWORD status = 0;
	DWORD retry_after_seconds = 0;
	std::string body;
};

// queries ipapi.co over HTTPS; callers use the status to avoid caching errors
HttpResponse https_get(const std::wstring& host, const std::wstring& path)
{
	HttpResponse result;
	HINTERNET	session = WinHttpOpen(L"lagsw/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!session)
	{
		LOG_DEBUG("https_get: WinHttpOpen failed %lu", GetLastError());
		return result;
	}
	WinHttpSetTimeouts(session, 3000, 3000, 3000, 3000);
	if (HINTERNET connect = WinHttpConnect(session, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0))
	{
		LOG_DEBUG("https_get: connected to host");
		if (HINTERNET request = WinHttpOpenRequest(connect,
													L"GET",
													path.c_str(),
													nullptr,
													WINHTTP_NO_REFERER,
													WINHTTP_DEFAULT_ACCEPT_TYPES,
													WINHTTP_FLAG_SECURE))
		{
			LOG_DEBUG("https_get: request opened, sending");
			if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
				WinHttpReceiveResponse(request, nullptr))
			{
				DWORD status		= 0;
				DWORD status_size = sizeof(status);
				if (WinHttpQueryHeaders(request,
										WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
										WINHTTP_HEADER_NAME_BY_INDEX,
										&status,
										&status_size,
										WINHTTP_NO_HEADER_INDEX))
				{
					result.status = status;
					// Retry-After can be a delta-seconds count or an HTTP-date, so it isn't queryable via WINHTTP_QUERY_FLAG_NUMBER
					DWORD retry_after_bytes = 0;
					WinHttpQueryHeaders(request,
										WINHTTP_QUERY_RETRY_AFTER,
										WINHTTP_HEADER_NAME_BY_INDEX,
										WINHTTP_NO_OUTPUT_BUFFER,
										&retry_after_bytes,
										WINHTTP_NO_HEADER_INDEX);
					if (retry_after_bytes > 0)
					{
						std::wstring retry_after_text(retry_after_bytes / sizeof(wchar_t), L'\0');
						if (WinHttpQueryHeaders(request,
												WINHTTP_QUERY_RETRY_AFTER,
												WINHTTP_HEADER_NAME_BY_INDEX,
												retry_after_text.data(),
												&retry_after_bytes,
												WINHTTP_NO_HEADER_INDEX))
						{
							retry_after_text.resize(wcsnlen(retry_after_text.c_str(), retry_after_text.size()));
							try
							{
								result.retry_after_seconds = std::stoul(retry_after_text);
							}
							catch (const std::exception&)
							{
								LOG_DEBUG("https_get: Retry-After header is not a delta-seconds value, ignoring");
							}
						}
					}
					LOG_DEBUG("https_get: response received, status %lu, reading body", status);
				}
				else
					LOG_DEBUG("https_get: response received, status unknown, reading body");
				DWORD available = 0;
				while (WinHttpQueryDataAvailable(request, &available) && available > 0)
				{
					std::vector<char> buffer(available);
					DWORD			  read = 0;
					if (!WinHttpReadData(request, buffer.data(), available, &read))
						break;
					result.body.append(buffer.data(), read);
				}
				LOG_DEBUG("https_get: finished reading %zu total bytes", result.body.size());
			}
			else
				LOG_DEBUG("https_get: send/receive failed %lu", GetLastError());
			WinHttpCloseHandle(request);
		}
		else
			LOG_DEBUG("https_get: WinHttpOpenRequest failed %lu", GetLastError());
		WinHttpCloseHandle(connect);
	}
	else
		LOG_DEBUG("https_get: WinHttpConnect failed %lu", GetLastError());
	WinHttpCloseHandle(session);
	return result;
}

HttpResponse https_get_until_not_rate_limited(const std::wstring& host, const std::wstring& path)
{
	while (true)
	{
		HttpResponse response = https_get(host, path);
		if (response.status != 429)
			return response;
		const DWORD delay_seconds = response.retry_after_seconds == 0 ? 1 : response.retry_after_seconds;
		LOG_DEBUG("https_get: rate limited, retrying in %lu second(s)", delay_seconds);
		const DWORD delay_ms = delay_seconds > (std::numeric_limits<DWORD>::max)() / 1000
			? (std::numeric_limits<DWORD>::max)()
			: delay_seconds * 1000;
		Sleep(delay_ms);
	}
}
}  // namespace

struct PacketEngine::Session
{
	explicit Session(int profile_number, HANDLE divert_handle, PacketMode* packet_mode)
	: profile(profile_number)
	, handle(divert_handle)
	, mode(packet_mode)
	{
	}

	int						profile;
	HANDLE					handle;
	std::atomic<bool>		stopping = false;
	std::mutex				packet_mutex;
	std::condition_variable packet_changed;
	uint64_t				next_receive_order = 0;
	PacketQueue				delayed_packets;
	PacketMode*				mode;
	std::thread				receive_thread;
	std::thread				send_thread;
};

struct PacketEngine::State
{
	struct ProfileStats
	{
		uint64_t			  enabled_since			= 0;
		uint64_t			  enabled_time_total	= 0;
		uint64_t			  enabled_time_min		= (std::numeric_limits<uint64_t>::max)();
		uint64_t			  enabled_time_max		= 0;
		uint64_t			  last_enabled_time		= 0;
		uint64_t			  enabled_count			= 0;
		std::atomic<uint64_t> packets_caught		= 0;
		std::atomic<uint64_t> delayed_packets_sent	= 0;
		std::atomic<uint64_t> teardown_packets_sent = 0;
	};

	explicit State(size_t profile_count) : profile_stats(profile_count) {}

	std::mutex								  lifecycle_mutex;
	std::condition_variable					  lifecycle_changed;
	std::vector<bool>						  active_profiles;
	std::vector<ProfileStats>				  profile_stats;
	std::vector<std::shared_ptr<Session>>	  active_sessions;
	std::vector<std::thread>				  cleanup_threads;
	HANDLE									  discovery_handle = INVALID_HANDLE_VALUE;
	std::thread								  discovery_thread;
	std::mutex								  discovery_mutex;
	std::string								  discovered_server;
	std::unordered_map<std::string, uint64_t> discovery_counts;
	bool									  authoritative_server		  = false;
	bool									  select_authoritative_server = false;
	std::mutex								  region_mutex;
	std::unordered_map<std::string, std::string> server_regions;
	std::unordered_map<std::string, RegionCacheEntry> region_cache;
	std::unordered_set<std::string>			  region_lookups_started;
	std::vector<std::thread>				  region_threads;
	std::string								  client_region;
};

PacketEngine::PacketEngine(PacketEngineOptions options) : options_(std::move(options)), state_(new State(options_.profiles.size()))
{
	load_region_cache(state_->region_cache);
	packet_modes_.reserve(options_.profiles.size());
	for (const ProfileOptions& profile : options_.profiles)
		packet_modes_.push_back(create_packet_mode(profile));
	state_->active_profiles.resize(options_.profiles.size());
	state_->active_sessions.resize(options_.profiles.size());
	std::unordered_set<std::string> logged_server_groups;
	for (const ServerOptions& server : options_.servers)
	{
		const std::string label = server.name == server.address ? server.address : server.name + " [" + server.address + "]";
		if (server.group.empty())
			LOG_INFO("Pre-configured server: %s", label.c_str());
		else
		{
			if (logged_server_groups.insert(server.group).second)
				LOG_INFO("Pre-configured server group '%s':", server.group.c_str());
			LOG_INFO("  %s", label.c_str());
		}
	}
	state_->select_authoritative_server = !options_.initial_server || *options_.initial_server == "none";
	if (options_.initial_server)
	{
		for (size_t index = 0; index < options_.servers.size(); ++index)
		{
			const ServerOptions& server = options_.servers[index];
			if (*options_.initial_server == server.address || *options_.initial_server == server.name)
			{
				server_index_ = index + 1;
				break;
			}
		}
		if (server_index_ == 0 && !state_->select_authoritative_server)
			LOG_WARN("Server '%s' does not exist; using none", options_.initial_server->c_str());
	}
	LOG_INFO("Initial server: %s", current_server().c_str());
}

PacketEngine::~PacketEngine()
{
	teardown();
	stop_workers();
}

bool PacketEngine::is_running() const
{
	return running_.load();
}

bool PacketEngine::is_running(int profile) const
{
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
		return false;
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	return state_->active_profiles[profile - 1];
}

bool PacketEngine::is_authoritative_server() const
{
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	return state_->authoritative_server;
}

uint64_t PacketEngine::running_time_ms() const
{
	const uint64_t				now = GetTickCount64();
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	uint64_t					earliest_enabled   = now;
	bool						has_active_profile = false;
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		if (state_->active_profiles[index])
		{
			has_active_profile = true;
			earliest_enabled   = (std::min)(earliest_enabled, state_->profile_stats[index].enabled_since);
		}
	}
	return has_active_profile ? now - earliest_enabled : 0;
}

size_t PacketEngine::pending_packets() const
{
	size_t						pending = 0;
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	for (const auto& session : state_->active_sessions)
		if (session)
		{
			std::lock_guard<std::mutex> session_lock(session->packet_mutex);
			pending += session->delayed_packets.size();
		}
	return pending;
}

uint64_t PacketEngine::next_batch_in_ms() const
{
	uint64_t					next_release	   = (std::numeric_limits<uint64_t>::max)();
	bool						has_queued_packets = false;
	const uint64_t				now				   = GetTickCount64();
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	for (const auto& session : state_->active_sessions)
		if (session)
		{
			std::lock_guard<std::mutex> session_lock(session->packet_mutex);
			if (!session->delayed_packets.empty())
			{
				has_queued_packets = true;
				next_release	   = (std::min)(next_release, session->delayed_packets.top()->release_at);
			}
		}
	if (!has_queued_packets)
		return 0;
	if (next_release == (std::numeric_limits<uint64_t>::max)())
		return (std::numeric_limits<uint64_t>::max)();
	return next_release > now ? next_release - now : 0;
}

std::string PacketEngine::server_filter(const ProfileOptions& profile) const
{
	const std::string& filter		= profile.filter.value_or(options_.global_filter);
	const size_t	   server_index = server_index_.load();
	if (server_index == 0 || !profile.windivert_options.server_direction)
		return filter;
	const std::string& server_address = options_.servers[server_index - 1].address;

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
	const std::string& server_group = options_.servers[server_index - 1].group;
	std::string address_filter;
	for (const ServerOptions& server : options_.servers)
	{
		if (server_group.empty() ? server.address == server_address : server.group == server_group)
		{
			if (!address_filter.empty())
				address_filter += " or ";
			address_filter += address_field + std::string(" == ") + server.address;
		}
	}
	return "(" + filter + ") and (" + address_filter + ")";
}

std::string PacketEngine::current_server() const
{
	std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
	const size_t				server_index = server_index_.load();
	if (server_index != 0)
	{
		const ServerOptions& server = options_.servers[server_index - 1];
		const std::string label = server.name == server.address ? server.address : server.name + " [" + server.address + "]";
		return server.group.empty() ? label : server.group + ": " + label;
	}
	return "none";
}

std::string PacketEngine::current_server_region() const
{
	std::string address;
	{
		std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
		const size_t				server_index = server_index_.load();
		if (server_index == 0)
			return "";
		address = options_.servers[server_index - 1].address;
	}
	std::lock_guard<std::mutex> region_lock(state_->region_mutex);
	const auto					 region = state_->server_regions.find(address);
	return region == state_->server_regions.end() ? "" : region->second;
}

std::string PacketEngine::client_region() const
{
	std::lock_guard<std::mutex> region_lock(state_->region_mutex);
	return state_->client_region;
}

void PacketEngine::cycle_server(int direction)
{
	if (options_.servers.empty() || direction == 0)
		return;
	const size_t option_count = options_.servers.size() + 1;
	size_t		 current	  = server_index_.load();
	if (direction > 0)
		current = (current + 1) % option_count;
	else
		current = current == 0 ? option_count - 1 : current - 1;
	server_index_						= current;
	state_->authoritative_server		= false;
	state_->select_authoritative_server = false;
	LOG_INFO("Server changed to: %s", current_server().c_str());

	std::vector<int> active_profiles;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		for (size_t index = 0; index < state_->active_profiles.size(); ++index)
			if (state_->active_profiles[index])
				active_profiles.push_back(static_cast<int>(index + 1));
	}
	for (const int profile : active_profiles)
		teardown(profile);
	for (const int profile : active_profiles)
		setup(profile);
}

void PacketEngine::print_state() const
{
	std::vector<bool> active_profiles;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		active_profiles = state_->active_profiles;
	}

	const size_t								  queued_packets  = pending_packets();
	const uint64_t								  next_release_in = next_batch_in_ms();
	std::vector<std::pair<std::string, uint64_t>> discovery_counts;
	std::string									  discovered_server;
	bool										  authoritative_server = false;
	{
		std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
		std::lock_guard<std::mutex> lock(state_->discovery_mutex);
		discovery_counts.assign(state_->discovery_counts.begin(), state_->discovery_counts.end());
		discovered_server	 = state_->discovered_server;
		authoritative_server = state_->authoritative_server;
	}
	std::sort(discovery_counts.begin(), discovery_counts.end(), [](const auto& left, const auto& right) {
		if (left.second != right.second)
			return left.second > right.second;
		return left.first < right.first;
	});

	size_t state_width = 53;
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		const std::string label = "profile #" + std::to_string(index + 1) + " - " + options_.profiles[index].name;
		if (label.size() + 4 > state_width)
			state_width = label.size() + 4;
	}
	const std::string max_value			 = std::to_string((std::numeric_limits<uint64_t>::max)());
	const size_t	  enabled_time_width = std::string("enabled time:    ").size() + max_value.size() + std::string("ms current, ").size() +
										   max_value.size() + std::string("ms min, ").size() + max_value.size() +
										   std::string("ms max, ").size() + max_value.size() + std::string("ms avg").size();
	if (enabled_time_width + 4 > state_width)
		state_width = enabled_time_width + 4;
	LOG_INFO("+%s+", std::string(state_width - 2, '-').c_str());
	log_state_line(state_width, "status:          " + highlight(running_ ? "RUNNING" : "STOPPED"));
	for (size_t index = 0; index < options_.profiles.size(); ++index)
	{
		const size_t			   profile_number		= index + 1;
		const ProfileOptions&	   profile_options		= options_.profiles[index];
		const State::ProfileStats& stats				= state_->profile_stats[index];
		uint64_t				   enabled_time_current = 0;
		uint64_t				   last_enabled_time	= 0;
		uint64_t				   enabled_time_min		= 0;
		uint64_t				   enabled_time_total	= 0;
		uint64_t				   enabled_time_max		= 0;
		uint64_t				   enabled_count		= 0;
		{
			std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
			if (active_profiles[index])
				enabled_time_current = GetTickCount64() - stats.enabled_since;
			enabled_time_total = stats.enabled_time_total;
			enabled_time_min   = stats.enabled_count == 0 ? 0 : stats.enabled_time_min;
			enabled_time_max   = stats.enabled_time_max;
			last_enabled_time  = stats.last_enabled_time;
			enabled_count	   = stats.enabled_count;
		}
		const uint64_t enabled_time_average = enabled_count == 0 ? 0 : enabled_time_total / enabled_count;
		std::string	   profile_label		= profile_options.name;
		if (active_profiles[index])
			profile_label += " (ACTIVE)";
		else if (enabled_count != 0)
			profile_label += " (held " + logging::format_duration(last_enabled_time) + ")";
		LOG_INFO("%s", format_state_divider(state_width, profile_label).c_str());
		log_state_line(state_width, "profile:         " + highlight("#" + std::to_string(profile_number) + " - " + profile_options.name));
		log_state_line(state_width,
					   "enabled time:    " + highlight(logging::format_duration(enabled_time_current)) + " current, " +
						   highlight(logging::format_duration(enabled_time_min)) + " min, " +
						   highlight(logging::format_duration(enabled_time_max)) + " max, " +
						   highlight(logging::format_duration(enabled_time_average)) + " avg");
		log_state_line(state_width,
					   "enabled total:   " + highlight(logging::format_duration(enabled_time_total)) + " across " +
						   highlight(std::to_string(enabled_count)) + " activations");
		log_state_line(state_width, "packets caught:  " + highlight(std::to_string(stats.packets_caught.load())));
		log_state_line(state_width, "sent after delay: " + highlight(std::to_string(stats.delayed_packets_sent.load())));
		log_state_line(state_width, "sent at teardown: " + highlight(std::to_string(stats.teardown_packets_sent.load())));
		LOG_INFO("%s", format_state_divider(state_width).c_str());
	}
	log_state_line(state_width, "queued packets:  " + highlight(std::to_string(queued_packets)));
	if (queued_packets != 0)
	{
		if (next_release_in == (std::numeric_limits<uint64_t>::max)())
			log_state_line(state_width, "next release:    " + highlight("on profile deactivation"));
		else
			log_state_line(state_width, "next release:    in " + highlight(logging::format_duration(next_release_in)));
	}
	if (options_.discovery_port)
	{
		std::unordered_map<std::string, std::string> server_regions;
		{
			std::lock_guard<std::mutex> lock(state_->region_mutex);
			server_regions = state_->server_regions;
		}
		LOG_DEBUG("print_state: snapshotted %zu resolved region(s)", server_regions.size());
		auto region_suffix = [&](const std::string& address) -> std::string {
			const auto region = server_regions.find(address);
			return region == server_regions.end() ? "" : " (" + region->second + ")";
		};
		LOG_INFO("%s", format_state_divider(state_width, "server discovery").c_str());
		log_state_line(state_width,
					   "authoritative:   " + highlight(discovered_server.empty() ? "none" : discovered_server + region_suffix(discovered_server)) +
						   (authoritative_server ? " (selected)" : " (observed)"));
		log_state_line(state_width, "ranked servers:  " + highlight(std::to_string(discovery_counts.size())));
		for (size_t index = 0; index < discovery_counts.size(); ++index)
		{
			const auto& [address, count] = discovery_counts[index];
			const auto		  server	 = std::find_if(options_.servers.begin(), options_.servers.end(), [&](const ServerOptions& item) {
				return item.address == address;
			});
			const std::string label =
				(server == options_.servers.end() || server->name == server->address ? address : server->name + " [" + address + "]") +
				region_suffix(address);
			log_state_line(state_width, std::to_string(index + 1) + ". " + label + " - " + highlight(std::to_string(count)) + " packets");
		}
		LOG_INFO("%s", format_state_divider(state_width).c_str());
	}
	LOG_INFO("+%s+", std::string(state_width - 2, '-').c_str());
}

void PacketEngine::read_packets(const std::shared_ptr<Session>& session)
{
	const int			  profile		  = session->profile;
	const ProfileOptions& profile_options = options_.profiles[profile - 1];
	const std::string	  profile_label	  = "profile #" + std::to_string(profile) + " - " + profile_options.name;
	while (!session->stopping)
	{
		BYTE			  packet_data[0xFFFF];
		WINDIVERT_ADDRESS address;
		UINT			  received_length = 0;
		if (!WinDivertRecv(session->handle, packet_data, sizeof(packet_data), &received_length, &address))
		{
			const DWORD error = GetLastError();
			if (!session->stopping && error != ERROR_INVALID_HANDLE && error != ERROR_OPERATION_ABORTED)
				LOG_ERROR("%s recv: WinDivertRecv error %lu: %s", profile_label.c_str(), error, format_win32_error(error).c_str());
			continue;
		}
		state_->profile_stats[profile - 1].packets_caught.fetch_add(1);
		const bool sniff = profile_options.windivert_options.sniff.value_or(false);
		if (!sniff)
		{
			std::lock_guard<std::mutex> lock(session->packet_mutex);
			if (session->stopping)
				break;
			session->mode->capture(packet_data,
								   received_length,
								   address,
								   session->profile,
								   GetTickCount64(),
								   session->next_receive_order++,
								   session->delayed_packets);
			session->packet_changed.notify_one();
		}
		PWINDIVERT_TCPHDR tcp_header = nullptr;
		const PacketAddresses addresses = packet_addresses(packet_data, received_length);
		if (WinDivertHelperParsePacket(packet_data,
									   received_length,
									   nullptr,
									   nullptr,
									   nullptr,
									   nullptr,
									   nullptr,
									   &tcp_header,
									   nullptr,
									   nullptr,
									   nullptr,
									   nullptr,
									   nullptr) &&
			tcp_header != nullptr)
		{
			LOG_DEBUG("%s recv: TCP packet: Length = %u, Sequence = %u, Ack = %u, Src = %s, Dst = %s",
					  profile_label.c_str(),
					  received_length,
					  WinDivertHelperNtohl(tcp_header->SeqNum),
					  WinDivertHelperNtohl(tcp_header->AckNum),
					  addresses.source.c_str(),
					  addresses.destination.c_str());
		}
		else
		{
			LOG_DEBUG("%s recv: packet: Length = %u, Src = %s, Dst = %s",
					  profile_label.c_str(),
					  received_length,
					  addresses.source.c_str(),
					  addresses.destination.c_str());
		}
	}
}

void PacketEngine::write_packets(const std::shared_ptr<Session>& session)

{
	const ProfileOptions& profile_options = options_.profiles[session->profile - 1];
	const std::string profile_label = "profile #" + std::to_string(session->profile) + " - " + profile_options.name;
	while (!session->stopping)
	{
		while (!session->stopping)
		{
			std::vector<PacketNode*> ready_packets;
			{
				std::unique_lock<std::mutex> lock(session->packet_mutex);
				while (session->delayed_packets.empty() && !session->stopping)
					session->packet_changed.wait(lock);
				if (session->stopping)
					break;

				const uint64_t now = GetTickCount64();
				if (session->delayed_packets.top()->release_at > now)
				{
					if (session->delayed_packets.top()->release_at == (std::numeric_limits<uint64_t>::max)())
						session->packet_changed.wait(lock);
					else
					{
						const uint64_t wait_ms = session->delayed_packets.top()->release_at - now;
						session->packet_changed.wait_for(lock, std::chrono::milliseconds(wait_ms));
					}
					continue;
				}
				session->mode->release(session->delayed_packets, now, ready_packets);
			}
			for (PacketNode* node : ready_packets)
			{
				UINT sent = 0;
				if (!WinDivertSend(session->handle, node->packet, node->length, &sent, node->address))
				{
					const DWORD error = GetLastError();
					LOG_ERROR("%s send: WinDivertSend failed %lu: %s", profile_label.c_str(), error, format_win32_error(error).c_str());
				}
				else if (sent != 0)
				{
					state_->profile_stats[session->profile - 1].delayed_packets_sent.fetch_add(1);
					const PacketAddresses addresses = packet_addresses(node->packet, node->length);
					LOG_DEBUG("%s send: delayed packet: Length = %u, Src = %s, Dst = %s, SendLen = %u",
							  profile_label.c_str(),
							  node->length,
							  addresses.source.c_str(),
							  addresses.destination.c_str(),
							  sent);
				}
			}
			for (size_t index = 0; index < ready_packets.size(); ++index)
			{
				PacketNode* node = ready_packets[index];
				destroy_packet_node(node);
			}
		}

		std::vector<PacketNode*> pending_packets;
		{
			std::lock_guard<std::mutex> lock(session->packet_mutex);
			session->mode->flush(session->delayed_packets, pending_packets);
		}
		for (PacketNode* node : pending_packets)
		{
			UINT sent = 0;
			if (!WinDivertSend(session->handle, node->packet, node->length, &sent, node->address))
			{
				const DWORD error = GetLastError();
				LOG_ERROR("%s flush: WinDivertSend failed %lu: %s", profile_label.c_str(), error, format_win32_error(error).c_str());
			}
			else if (sent != 0)
			{
				state_->profile_stats[session->profile - 1].teardown_packets_sent.fetch_add(1);
				const PacketAddresses addresses = packet_addresses(node->packet, node->length);
				LOG_DEBUG("%s flush: sent packet: Length = %u, Src = %s, Dst = %s, SendLen = %u",
						  profile_label.c_str(),
						  node->length,
						  addresses.source.c_str(),
						  addresses.destination.c_str(),
						  sent);
			}
			destroy_packet_node(node);
		}
	}
	LOG_DEBUG("%s flush: stopped", profile_label.c_str());
}

void PacketEngine::setup(int profile)
{
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
	{
		LOG_ERROR("Profile %d is not configured", profile);
		return;
	}
	if (state_->active_sessions[profile - 1])
		return;
	timeBeginPeriod(1);
	const ProfileOptions& profile_options = options_.profiles[profile - 1];
	const bool			  sniff			  = profile_options.windivert_options.sniff.value_or(false);
	const bool			  outbound		  = profile_options.windivert_options.outbound.value_or(false);
	const bool			  forward		  = profile_options.windivert_options.forward.value_or(false);
	const std::string	  filter		  = server_filter(profile_options);
	UINT				  flags			  = sniff ? WINDIVERT_FLAG_SNIFF : 0;
	const std::string	  capture_filter  = outbound ? "outbound and (" + filter + ")" : filter;
	const WINDIVERT_LAYER layer			  = forward ? WINDIVERT_LAYER_NETWORK_FORWARD : WINDIVERT_LAYER_NETWORK;
	HANDLE				  handle		  = WinDivertOpen(capture_filter.c_str(), layer, 0, flags);
	if (handle == INVALID_HANDLE_VALUE)
	{
		const DWORD error = GetLastError();
		LOG_ERROR("profile #%d - %s setup: failed to open WinDivert handle %lu: %s",
				  profile,
				  profile_options.name.c_str(),
				  error,
				  format_win32_error(error).c_str());
		timeEndPeriod(1);
		return;
	}
	std::shared_ptr<Session> session(new Session(profile, handle, packet_modes_[profile - 1].get()));
	state_->profile_stats[profile - 1].enabled_since = GetTickCount64();
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
	WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 1024);
	state_->active_sessions[profile - 1] = session;
	state_->active_profiles[profile - 1] = true;
	{
		std::lock_guard<std::mutex> discovery_lock(state_->discovery_mutex);
		state_->discovery_counts.clear();
	}
	packet_modes_[profile - 1]->reset();
	running_				= true;
	session->receive_thread = std::thread(&PacketEngine::read_packets, this, session);
	session->send_thread	= std::thread(&PacketEngine::write_packets, this, session);
	LOG_DEBUG("profile #%d - %s setup: opening handle", profile, profile_options.name.c_str());
	LOG_DEBUG("profile #%d - %s setup: WinDivert layer = %s, filter = %s",
			  profile,
			  profile_options.name.c_str(),
			  forward ? "NETWORK_FORWARD" : "NETWORK",
			  capture_filter.c_str());
	LOG_INFO("Lag switch enabled, profile = %s (%s, mode = %s). %s",
			 profile_options.name.c_str(),
			 format_keys(profile_options).c_str(),
			 profile_options.mode == ProfileActivationMode::hold ? "hold" : "toggle",
			 profile_options.mode == ProfileActivationMode::hold ? "Release key(s) to turn off" : "Press key(s) again to turn off");
}

bool PacketEngine::toggle(int profile)
{
	std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
	if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
		return false;
	const std::shared_ptr<Session>& session = state_->active_sessions[profile - 1];
	if (!session)
		return false;
	std::lock_guard<std::mutex> packet_lock(session->packet_mutex);
	const bool					release = session->mode->toggle(session->delayed_packets);
	session->packet_changed.notify_all();
	return release;
}

void PacketEngine::teardown(int profile)
{
	LOG_DEBUG("profile #%d teardown: requested", profile);
	uint64_t				 enabled_time = 0;
	std::shared_ptr<Session> session;
	{
		std::lock_guard<std::mutex> lock(state_->lifecycle_mutex);
		if (profile < 1 || static_cast<size_t>(profile) > options_.profiles.size())
			return;
		session = state_->active_sessions[profile - 1];
		if (!session)
			return;
		LOG_DEBUG("profile #%d - %s teardown: stopping workers", profile, options_.profiles[profile - 1].name.c_str());
		State::ProfileStats& stats = state_->profile_stats[profile - 1];
		enabled_time			   = GetTickCount64() - stats.enabled_since;
		stats.last_enabled_time	   = enabled_time;
		stats.enabled_time_total += enabled_time;
		if (enabled_time < stats.enabled_time_min)
			stats.enabled_time_min = enabled_time;
		if (enabled_time > stats.enabled_time_max)
			stats.enabled_time_max = enabled_time;
		++stats.enabled_count;
		state_->active_sessions[profile - 1].reset();
		state_->active_profiles[profile - 1] = false;
		running_		  = std::any_of(state_->active_profiles.begin(), state_->active_profiles.end(), [](bool active) { return active; });
		session->stopping = true;
		WinDivertShutdown(session->handle, WINDIVERT_SHUTDOWN_RECV);
		session->packet_changed.notify_all();
		state_->cleanup_threads.emplace_back([this, session, enabled_time, profile] {
			session->receive_thread.join();
			session->send_thread.join();
			WinDivertClose(session->handle);
			timeEndPeriod(1);
			LOG_INFO("profile #%d - %s teardown: disabled after %s",
					 profile,
					 options_.profiles[profile - 1].name.c_str(),
					 logging::format_duration(enabled_time).c_str());
		});
	}
}

void PacketEngine::teardown()
{
	for (size_t index = 0; index < options_.profiles.size(); ++index)
		teardown(static_cast<int>(index + 1));
}

void PacketEngine::start_workers()
{
	if (options_.resolve_region)
		resolve_client_region();
	if (!options_.discovery_port)
		return;
	const uint16_t	  port	 = *options_.discovery_port;
	const std::string filter = "tcp.DstPort == " + std::to_string(port) + " or tcp.SrcPort == " + std::to_string(port) +
							   " or udp.DstPort == " + std::to_string(port) + " or udp.SrcPort == " + std::to_string(port);
	state_->discovery_handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);
	if (state_->discovery_handle == INVALID_HANDLE_VALUE)
	{
		const DWORD error = GetLastError();
		LOG_ERROR("Server discovery setup: failed to open WinDivert handle %lu: %s", error, format_win32_error(error).c_str());
		return;
	}
	WinDivertSetParam(state_->discovery_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 4096);
	WinDivertSetParam(state_->discovery_handle, WINDIVERT_PARAM_QUEUE_TIME, 1024);
	LOG_INFO("Server discovery enabled on port %u with a %s window", port, logging::format_duration(options_.discovery_window_ms).c_str());
	state_->discovery_thread = std::thread(&PacketEngine::discover_packets, this);
}

void PacketEngine::stop_workers()
{
	shutdown_ = true;
	if (state_->discovery_handle != INVALID_HANDLE_VALUE)
		WinDivertShutdown(state_->discovery_handle, WINDIVERT_SHUTDOWN_RECV);
	teardown();
	for (std::thread& cleanup_thread : state_->cleanup_threads)
		if (cleanup_thread.joinable())
			cleanup_thread.join();
	if (state_->discovery_thread.joinable())
		state_->discovery_thread.join();
	for (std::thread& region_thread : state_->region_threads)
		if (region_thread.joinable())
			region_thread.join();
	state_->region_threads.clear();
	if (state_->discovery_handle != INVALID_HANDLE_VALUE)
	{
		WinDivertClose(state_->discovery_handle);
		state_->discovery_handle = INVALID_HANDLE_VALUE;
	}
}

void PacketEngine::resolve_region(const std::string& address)
{
	RegionCacheEntry cached;
	{
		std::lock_guard<std::mutex> lock(state_->region_mutex);
		const auto cache_entry = state_->region_cache.find(address);
		if (cache_entry != state_->region_cache.end() && cache_entry->second.expires_at > static_cast<uint64_t>(std::time(nullptr)))
		{
			cached = cache_entry->second;
			state_->server_regions[address] = cached.label;
		}
	}
	if (!cached.label.empty())
	{
		LOG_DEBUG("Region lookup for '%s': using local cache", address.c_str());
		// resolve_region is only ever called by discover_packets, which already holds lifecycle_mutex here
		if (!cached.server_name.empty())
		{
			const auto server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](ServerOptions& item) {
				return item.address == address;
			});
			if (server != options_.servers.end())
				server->name = cached.server_name;
		}
		return;
	}
	{
		std::lock_guard<std::mutex> lock(state_->region_mutex);
		if (!state_->region_lookups_started.insert(address).second)
		{
			LOG_DEBUG("Region lookup for '%s': already started, skipping", address.c_str());
			return;
		}
	}
	LOG_DEBUG("Region lookup for '%s': queued", address.c_str());
	state_->region_threads.emplace_back([this, address] {
		LOG_DEBUG("Region lookup for '%s': requesting https://ipapi.co/%s/json/", address.c_str(), address.c_str());
		const std::wstring path	   = L"/" + std::wstring(address.begin(), address.end()) + L"/json/";
		const HttpResponse response = https_get_until_not_rate_limited(L"ipapi.co", path);
		if (response.status < 200 || response.status >= 300 || response.body.empty())
		{
			LOG_DEBUG("Region lookup for '%s': unsuccessful response (status %lu), giving up", address.c_str(), response.status);
			return;
		}
		LOG_DEBUG("Region lookup for '%s': received %zu byte response", address.c_str(), response.body.size());
		const auto label = extract_region_label(response.body);
		if (!label)
		{
			LOG_DEBUG("Region lookup for '%s': response missing region/country fields, body: %s",
					  address.c_str(),
					  response.body.substr(0, 300).c_str());
			return;
		}
		const std::string new_name = build_server_name(address, response.body);
		{
			std::lock_guard<std::mutex> lock(state_->region_mutex);
			state_->server_regions[address] = *label;
			state_->region_cache[address] = {*label, new_name, static_cast<uint64_t>(std::time(nullptr)) + region_cache_lifetime_seconds};
			save_region_cache(state_->region_cache);
		}
		LOG_DEBUG("Region lookup for '%s': cached result", address.c_str());
		LOG_INFO("Resolved region for server '%s': %s", address.c_str(), label->c_str());

		LOG_DEBUG("Region lookup for '%s': rewriting server name to '%s'", address.c_str(), new_name.c_str());
		{
			std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
			const auto					 server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](ServerOptions& item) {
				return item.address == address;
			});
			if (server != options_.servers.end())
				server->name = new_name;
			else
				LOG_DEBUG("Region lookup for '%s': server no longer tracked, skipping rename", address.c_str());
		}
		LOG_INFO("Server '%s' renamed to '%s'", address.c_str(), new_name.c_str());
	});
}

void PacketEngine::resolve_client_region()
{
	{
		std::lock_guard<std::mutex> lock(state_->region_mutex);
		const auto cache_entry = state_->region_cache.find(client_region_cache_key);
		if (cache_entry != state_->region_cache.end() && cache_entry->second.expires_at > static_cast<uint64_t>(std::time(nullptr)))
		{
			state_->client_region = cache_entry->second.label;
			LOG_DEBUG("Client region lookup: using local cache");
			return;
		}
	}
	LOG_DEBUG("Client region lookup: queued");
	state_->region_threads.emplace_back([this] {
		LOG_DEBUG("Client region lookup: requesting https://ipapi.co/json/");
		const HttpResponse response = https_get_until_not_rate_limited(L"ipapi.co", L"/json/");
		if (response.status < 200 || response.status >= 300 || response.body.empty())
		{
			LOG_DEBUG("Client region lookup: unsuccessful response (status %lu), giving up", response.status);
			return;
		}
		LOG_DEBUG("Client region lookup: received %zu byte response", response.body.size());
		const auto label = extract_region_label(response.body);
		if (!label)
		{
			LOG_DEBUG("Client region lookup: response missing region/country fields, body: %s", response.body.substr(0, 300).c_str());
			return;
		}
		{
			std::lock_guard<std::mutex> lock(state_->region_mutex);
			state_->client_region = *label;
			state_->region_cache[client_region_cache_key] = {*label, "", static_cast<uint64_t>(std::time(nullptr)) + region_cache_lifetime_seconds};
			save_region_cache(state_->region_cache);
		}
		LOG_DEBUG("Client region lookup: cached result");
		LOG_INFO("Resolved client region: %s", label->c_str());
	});
}

void PacketEngine::discover_packets()
{
	std::unordered_map<std::string, uint64_t> packet_counts;
	std::unordered_set<std::string>			  seen_servers;
	auto									  format_server_label = [&](const std::string& address) {
		const auto server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](const ServerOptions& item) {
			return item.address == address;
		});
		return server == options_.servers.end() ? address : server->name + " [" + address + "]";
	};
	uint64_t window_started = GetTickCount64();
	bool	 was_running	= false;
	BYTE	 packet_data[0xFFFF];
	while (!shutdown_)
	{
		WINDIVERT_ADDRESS address;
		UINT			  received_length = 0;
		if (WinDivertRecv(state_->discovery_handle, packet_data, sizeof(packet_data), &received_length, &address))
		{
			if (running_.load())
			{
				if (!was_running)
					LOG_DEBUG("Server discovery disabled while a profile is active");
				was_running = true;
				packet_counts.clear();
				std::lock_guard<std::mutex> lock(state_->discovery_mutex);
				state_->discovery_counts.clear();
				window_started = GetTickCount64();
				continue;
			}
			if (was_running)
			{
				LOG_DEBUG("Server discovery enabled after all profiles were deactivated");
				was_running	   = false;
				window_started = GetTickCount64();
			}
			PWINDIVERT_IPHDR   ip_header   = nullptr;
			PWINDIVERT_IPV6HDR ipv6_header = nullptr;
			if (WinDivertHelperParsePacket(packet_data,
										   received_length,
										   &ip_header,
										   &ipv6_header,
										   nullptr,
										   nullptr,
										   nullptr,
										   nullptr,
										   nullptr,
										   nullptr,
										   nullptr,
										   nullptr,
										   nullptr))
			{
				std::string address_text;
				if (ip_header)
					address_text = format_ipv4_address(address.Outbound ? ip_header->DstAddr : ip_header->SrcAddr);
				else if (ipv6_header)
					address_text = format_ipv6_address(address.Outbound ? ipv6_header->DstAddr : ipv6_header->SrcAddr);
				if (!address_text.empty())
				{
					std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
					const bool					first_seen = seen_servers.insert(address_text).second;
					auto existing_server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](const ServerOptions& server) {
						return server.address == address_text;
					});
					const bool configured_server = existing_server != options_.servers.end();
					if (existing_server == options_.servers.end())
					{
						options_.servers.push_back({address_text, address_text});
						existing_server = options_.servers.end() - 1;
					}
					if (first_seen)
					{
						const std::string server_label = format_server_label(address_text);
						LOG_INFO("Server '%s' is potentially the authoritative server (first packet received)", server_label.c_str());
						if (options_.resolve_region && !configured_server)
						{
							if (is_public_address(address_text))
							{
								LOG_DEBUG("Server discovery: '%s' is public, triggering region lookup", address_text.c_str());
								resolve_region(address_text);
							}
							else
								LOG_DEBUG("Server discovery: '%s' is private/local, skipping region lookup", address_text.c_str());
						}
						else if (options_.resolve_region && configured_server)
							LOG_DEBUG("Server discovery: '%s' is already configured, skipping region lookup", address_text.c_str());
					}
					++packet_counts[address_text];
					state_->discovery_counts = packet_counts;
				}
			}
		}
		else if (!shutdown_)
		{
			const DWORD error = GetLastError();
			if (error != ERROR_INVALID_HANDLE && error != ERROR_OPERATION_ABORTED)
				LOG_ERROR("Server discovery recv: WinDivertRecv error %lu: %s", error, format_win32_error(error).c_str());
		}

		const uint64_t now = GetTickCount64();
		if (now - window_started < options_.discovery_window_ms)
			continue;
		if (!packet_counts.empty())
		{
			const auto winner = std::max_element(packet_counts.begin(), packet_counts.end(), [](const auto& left, const auto& right) {
				return left.second < right.second;
			});
			std::lock_guard<std::mutex> lifecycle_lock(state_->lifecycle_mutex);
			std::lock_guard<std::mutex> lock(state_->discovery_mutex);
			if (state_->discovered_server != winner->first)
			{
				auto existing_server = std::find_if(options_.servers.begin(), options_.servers.end(), [&](const ServerOptions& server) {
					return server.address == winner->first;
				});
				if (existing_server == options_.servers.end())
				{
					options_.servers.push_back({winner->first, winner->first});
					existing_server = options_.servers.end() - 1;
				}
				else
					LOG_WARN("Discovered server '%s' already exists in the server list; switching to '%s'",
							 winner->first.c_str(),
							 existing_server->name.c_str());
				state_->discovered_server	   = winner->first;
				const std::string server_label = format_server_label(winner->first);
				LOG_INFO("Server '%s' is the authoritative server (%llu packets in %s)",
						 server_label.c_str(),
						 static_cast<unsigned long long>(winner->second),
						 logging::format_duration(options_.discovery_window_ms).c_str());
				if (state_->select_authoritative_server || state_->authoritative_server)
				{
					state_->authoritative_server		= true;
					state_->select_authoritative_server = false;
					server_index_						= static_cast<size_t>(std::distance(options_.servers.begin(), existing_server)) + 1;
				}
			}
		}
		packet_counts.clear();
		{
			std::lock_guard<std::mutex> lock(state_->discovery_mutex);
			state_->discovery_counts.clear();
		}
		window_started = now;
	}
}