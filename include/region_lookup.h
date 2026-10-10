#ifndef REGION_LOOKUP_H_
#define REGION_LOOKUP_H_

#include <windows.h>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

struct RegionCacheEntry
{
	std::string label;
	std::string server_name;
	uint64_t	expires_at = 0;
};

inline constexpr uint64_t region_cache_lifetime_seconds = 30 * 24 * 60 * 60;
inline constexpr const char* client_region_cache_key	= "@client";

bool is_public_address(const std::string& address);
std::string build_server_name(const std::string& address, const std::string& response);
std::optional<std::string> extract_region_label(const std::string& response);

void load_region_cache(std::unordered_map<std::string, RegionCacheEntry>& cache);
void save_region_cache(const std::unordered_map<std::string, RegionCacheEntry>& cache);

struct HttpResponse
{
	DWORD		status				= 0;
	DWORD		retry_after_seconds = 0;
	std::string body;
};

HttpResponse https_get_until_not_rate_limited(const std::wstring& host, const std::wstring& path);

#endif
