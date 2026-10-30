#include "region_lookup.h"

#include <cctype>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

#include "log.h"

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
	const auto value_end   = json.find('"', value_start);
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
	while (end < json.size() &&
		   (std::isdigit(static_cast<unsigned char>(json[end])) || json[end] == '-' || json[end] == '+' || json[end] == '.'))
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
								const std::optional<double>&	  longitude)
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
	const std::string	group	= country_code && *country_code == "US" ? "US" : continent_code.value_or(country_code.value_or("XX"));
	const auto			band_it = longitude_bands.find(group);
	const LongitudeBand band	= band_it == longitude_bands.end() ? LongitudeBand{-30.0, 30.0} : band_it->second;
	const double		lon		= longitude.value_or(0.0);
	const char			suffix	= lon < band.west_max ? 'W' : lon > band.east_min ? 'E' : 'C';
	return group + suffix;
}

// e.g. "IA-USC-19" for region_code IA, country_region USC, and address ending in .19
std::string build_server_name(const std::string& address, const std::string& response)
{
	const auto region_code	  = extract_json_string(response, "region_code");
	const auto country_code	  = extract_json_string(response, "country_code");
	const auto continent_code = extract_json_string(response, "continent_code");
	const auto longitude	  = extract_json_number(response, "longitude");
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

std::string region_cache_path()
{
	const std::string directory = platform::data_directory();
	if (directory.empty())
		return {};
	return directory + "/region-cache.csv";
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
	std::string				 field;
	bool					 quoted = false;
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
	bool		  legacy_tsv = false;
	if (!file)
	{
		const std::string legacy_path = path.substr(0, path.size() - 4) + ".tsv";
		file.open(legacy_path);
		legacy_tsv = true;
	}
	const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
	std::string	   line;
	while (std::getline(file, line))
	{
		std::optional<std::vector<std::string>> fields;
		if (legacy_tsv)
		{
			fields		 = std::vector<std::string>();
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
			LOG_DEBUG_GROUP(logging::group::region, "Ignoring malformed region cache entry");
		}
	}
}

void save_region_cache(const std::unordered_map<std::string, RegionCacheEntry>& cache)
{
	const std::string path = region_cache_path();
	if (path.empty())
		return;
	const std::string directory = path.substr(0, path.find_last_of("\\/"));
	platform::make_directory(directory);
	const std::string temporary_path = path + ".tmp";
	std::ofstream	  file(temporary_path, std::ios::trunc);
	if (!file)
		return;
	for (const auto& [address, entry] : cache)
		file << csv_field(address) << ',' << csv_field(entry.label) << ',' << csv_field(entry.server_name) << ',' << entry.expires_at
			 << '\n';
	file.close();
	platform::replace_file(temporary_path, path);
}

HttpResponse https_get_until_not_rate_limited(const std::string& host, const std::string& path)
{
	while (true)
	{
		HttpResponse response = platform::https_get(host, path);
		if (response.status != 429)
			return response;
		const uint32_t delay_seconds = response.retry_after_seconds == 0 ? 1 : response.retry_after_seconds;
		LOG_DEBUG_GROUP(logging::group::http, "https_get: rate limited, retrying in %u second(s)", delay_seconds);
		const uint32_t delay_ms =
			delay_seconds > (std::numeric_limits<uint32_t>::max)() / 1000 ? (std::numeric_limits<uint32_t>::max)() : delay_seconds * 1000;
		platform::sleep_ms(delay_ms);
	}
}
