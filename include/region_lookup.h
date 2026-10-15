#ifndef REGION_LOOKUP_H_
#define REGION_LOOKUP_H_

#include <windows.h>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

/// Cached region label and resolved server name, with an expiration timestamp.
struct RegionCacheEntry
{
	/// Region label returned by the lookup service.
	std::string label;
	/// Resolved server display name.
	std::string server_name;
	/// Cache expiration time as a Unix timestamp.
	uint64_t	expires_at = 0;
};

/// Lifetime of cached region lookups, in seconds.
inline constexpr uint64_t region_cache_lifetime_seconds = 30 * 24 * 60 * 60;
/// Cache key used for the locally resolved client region.
inline constexpr const char* client_region_cache_key	= "@client";

/// Returns whether an IP address is publicly routable.
bool is_public_address(const std::string& address);
/// Builds a display name for a server from its address and lookup response.
std::string build_server_name(const std::string& address, const std::string& response);
/// Extracts a region label from a lookup response, if one is present.
std::optional<std::string> extract_region_label(const std::string& response);

/// Loads persisted region entries into the supplied cache.
void load_region_cache(std::unordered_map<std::string, RegionCacheEntry>& cache);
/// Persists the supplied region cache.
void save_region_cache(const std::unordered_map<std::string, RegionCacheEntry>& cache);

/// HTTP status, retry delay, and response body returned by an HTTPS request.
struct HttpResponse
{
	/// HTTP response status code.
	DWORD		status				= 0;
	/// Server-provided delay before retrying a rate-limited request.
	DWORD		retry_after_seconds = 0;
	/// Response body.
	std::string body;
};

/// Sends an HTTPS GET request, retrying rate-limited responses when instructed.
HttpResponse https_get_until_not_rate_limited(const std::wstring& host, const std::wstring& path);

#endif
