// Unit tests for the region lookup helpers (src/packet_engine/region_lookup.cc): response parsing, server naming, the on-disk
// cache and rate-limit retries. The platform services it relies on (data directory, HTTPS, sleeping) are replaced by fakes.
#include <algorithm>
#include <cstdint>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "log.h"
#include "region_lookup.h"
#include "support/test.h"

namespace {
std::string										 fake_data_directory;
std::deque<platform::HttpResponse>				 scripted_responses;
std::vector<std::pair<std::string, std::string>> requests;
std::vector<uint32_t>							 sleeps;
}  // namespace

namespace platform {
std::string data_directory()
{
	return fake_data_directory;
}

void make_directory(const std::string& path)
{
	std::error_code ignored;
	std::filesystem::create_directories(path, ignored);
}

bool replace_file(const std::string& source, const std::string& destination)
{
	std::error_code error;
	std::filesystem::remove(destination, error);
	std::filesystem::rename(source, destination, error);
	if (error)
		std::filesystem::remove(source, error);
	return !error;
}

HttpResponse https_get(const std::string& host, const std::string& path)
{
	requests.emplace_back(host, path);
	if (scripted_responses.empty())
		return {};
	HttpResponse response = scripted_responses.front();
	scripted_responses.pop_front();
	return response;
}

void sleep_ms(uint32_t milliseconds)
{
	sleeps.push_back(milliseconds);
}
}  // namespace platform

namespace {
using Cache = std::unordered_map<std::string, RegionCacheEntry>;

uint64_t now_seconds()
{
	return static_cast<uint64_t>(std::time(nullptr));
}

/// A fresh data directory for the duration of one test; platform::data_directory() points at it.
class DataDirectory
{
public:
	DataDirectory()
	{
		path_ = std::filesystem::temp_directory_path() / "lagsw_region_test";
		std::filesystem::remove_all(path_);
		std::filesystem::create_directories(path_);
		fake_data_directory = path_.string();
	}
	~DataDirectory()
	{
		fake_data_directory.clear();
		std::filesystem::remove_all(path_);
	}
	DataDirectory(const DataDirectory&)			   = delete;
	DataDirectory& operator=(const DataDirectory&) = delete;

	std::filesystem::path file(const std::string& name) const { return path_ / name; }

	void write(const std::string& name, const std::string& text) const
	{
		std::ofstream out(file(name), std::ios::binary);
		out << text;
	}

	// Normalize line endings: the cache is written in text mode, so Windows produces CRLF.
	std::string read(const std::string& name) const
	{
		std::ifstream in(file(name), std::ios::binary);
		std::string	  text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
		text.erase(std::remove(text.begin(), text.end(), '\r'), text.end());
		return text;
	}

private:
	std::filesystem::path path_;
};

void reset_fakes()
{
	scripted_responses.clear();
	requests.clear();
	sleeps.clear();
}

void test_private_addresses_are_not_public()
{
	const char* local[] = {"",			"10.0.0.1",	  "10.255.255.255", "127.0.0.1",  "192.168.1.1", "169.254.10.10", "::1",
						   "fe80::1",	"fc00::1",	  "fd12:3456::1",	"172.16.0.1", "172.20.5.5",	 "172.31.255.255"};
	for (const char* address : local)
	{
		if (is_public_address(address))
			std::fprintf(stderr, "address '%s' should not be public\n", address);
		CHECK(!is_public_address(address));
	}
}

void test_public_addresses()
{
	const char* routable[] = {"8.8.8.8",	"34.13.202.203", "1.1.1.1",		"100.64.0.1", "100.1.1.1",	"192.169.0.1",
							  "11.0.0.1", "172.15.255.255", "172.32.0.1", "2001:db8::1", "2606:4700::1111"};
	for (const char* address : routable)
	{
		if (!is_public_address(address))
			std::fprintf(stderr, "address '%s' should be public\n", address);
		CHECK(is_public_address(address));
	}
	// A 172.* string that is not a dotted quad is not mistaken for a private range.
	CHECK(is_public_address("172.5"));
	CHECK(is_public_address("172.abc.1.1"));
}

void test_extract_region_label()
{
	CHECK(extract_region_label(R"({"region": "Iowa", "country_name": "United States"})") == std::optional<std::string>("Iowa, United States"));
	CHECK(extract_region_label(R"({"region":"Iowa","country_name":"United States"})") == std::optional<std::string>("Iowa, United States"));
	CHECK(extract_region_label("{\"region\":\t\"Hesse\",\"country_name\":  \"Germany\"}") == std::optional<std::string>("Hesse, Germany"));
	CHECK(extract_region_label(R"({"country_name": "Singapore"})") == std::optional<std::string>("Singapore"));
	CHECK(extract_region_label(R"({"region": "Bavaria"})") == std::optional<std::string>("Bavaria"));
	CHECK(extract_region_label(R"({"region": null, "country_name": "France"})") == std::optional<std::string>("France"));

	CHECK(!extract_region_label("").has_value());
	CHECK(!extract_region_label(R"({"error": true, "reason": "RateLimited"})").has_value());
	CHECK(!extract_region_label(R"({"region": null, "country_name": null})").has_value());
	CHECK(!extract_region_label(R"({"region": "Unterminated)").has_value());
	// region_code and country_code are different keys and must not be mistaken for the label fields.
	CHECK(!extract_region_label(R"({"region_code": "IA", "country_code": "US"})").has_value());
}

void test_build_server_name_splits_the_us_into_longitude_bands()
{
	const auto name = [](const char* longitude) {
		return build_server_name("34.1.2.19", std::string(R"({"region_code": "IA", "country_code": "US", "continent_code": "NA", "longitude": )") + longitude + "}");
	};
	CHECK(name("-122.4") == "IA-USW-19");
	CHECK(name("-93.6") == "IA-USC-19");
	CHECK(name("-75.1") == "IA-USE-19");
	// The band edges belong to the central region.
	CHECK(name("-115.1") == "IA-USW-19");
	CHECK(name("-115") == "IA-USC-19");
	CHECK(name("-90") == "IA-USC-19");
	CHECK(name("-89.9") == "IA-USE-19");
}

void test_build_server_name_for_other_regions()
{
	const auto name = [](const char* address, const char* region, const char* country, const char* continent, const char* longitude) {
		return build_server_name(address, std::string("{\"region_code\": \"") + region + "\", \"country_code\": \"" + country + "\", \"continent_code\": \"" + continent +
											  "\", \"longitude\": " + longitude + "}");
	};
	CHECK(name("35.0.0.7", "HE", "DE", "EU", "8.6") == "HE-EUC-7");
	CHECK(name("35.0.0.7", "ENG", "GB", "EU", "-9.0") == "ENG-EUW-7");
	CHECK(name("35.0.0.7", "MOW", "RU", "EU", "37.6") == "MOW-EUE-7");
	CHECK(name("35.0.0.3", "13", "JP", "AS", "139.7") == "13-ASE-3");
	CHECK(name("35.0.0.3", "SG", "SG", "AS", "103.8") == "SG-ASC-3");
	CHECK(name("35.0.0.3", "NSW", "AU", "OC", "151.2") == "NSW-OCE-3");
	CHECK(name("35.0.0.3", "SP", "BR", "SA", "-46.6") == "SP-SAE-3");
	// Canada is grouped with the rest of North America, only the US gets its own bands.
	CHECK(name("35.0.0.3", "BC", "CA", "NA", "-123.1") == "BC-NAW-3");
}

void test_build_server_name_falls_back_for_missing_fields()
{
	CHECK(build_server_name("1.2.3.4", "{}") == "XX-XXC-4");
	CHECK(build_server_name("1.2.3.4", R"({"region_code": "ON"})") == "ON-XXC-4");
	// Without a continent the country code names the group; unknown groups use a wide central band.
	CHECK(build_server_name("1.2.3.4", R"({"country_code": "FR", "longitude": 2.3})") == "XX-FRC-4");
	CHECK(build_server_name("1.2.3.4", R"({"country_code": "FR", "longitude": 40})") == "XX-FRE-4");
	CHECK(build_server_name("1.2.3.4", R"({"country_code": "FR", "longitude": -40})") == "XX-FRW-4");
	CHECK(build_server_name("1.2.3.4", R"({"country_code": "US", "longitude":-122})") == "XX-USW-4");
	// A longitude that is not a number counts as 0, which is on the east side of the US bands.
	CHECK(build_server_name("1.2.3.4", R"({"country_code": "US", "longitude": "-122"})") == "XX-USE-4");
}

void test_build_server_name_uses_the_last_address_segment()
{
	CHECK(build_server_name("34.13.202.203", "{}") == "XX-XXC-203");
	CHECK(build_server_name("2001:db8::abcd", "{}") == "XX-XXC-abcd");
	CHECK(build_server_name("::ffff:1.2.3.4", "{}") == "XX-XXC-4");
	CHECK(build_server_name("hostname", "{}") == "XX-XXC-hostname");
}

void test_cache_round_trip()
{
	DataDirectory  directory;
	const uint64_t future = now_seconds() + 1000;

	Cache saved;
	saved["34.1.2.3"]			   = {"Iowa, United States", "IA-USC-3", future};
	saved["34.1.2.4"]			   = {"Quote \"inside\"", "name, with comma", future + 5};
	saved[client_region_cache_key] = {"Berlin, Germany", "", future + 10};
	save_region_cache(saved);

	Cache loaded;
	load_region_cache(loaded);
	CHECK(loaded.size() == 3);
	for (const auto& [address, entry] : saved)
	{
		const auto found = loaded.find(address);
		CHECK(found != loaded.end());
		if (found == loaded.end())
			continue;
		CHECK(found->second.label == entry.label && found->second.server_name == entry.server_name && found->second.expires_at == entry.expires_at);
	}
}

void test_cache_file_format()
{
	DataDirectory directory;
	Cache		  cache;
	cache["1.2.3.4"] = {"Iowa, United States", "IA-USC-4", 4102444800};
	save_region_cache(cache);
	CHECK(directory.read("region-cache.csv") == "1.2.3.4,\"Iowa, United States\",IA-USC-4,4102444800\n");

	cache.clear();
	cache["5.6.7.8"] = {"say \"hi\"", "", 4102444801};
	save_region_cache(cache);
	CHECK(directory.read("region-cache.csv") == "5.6.7.8,\"say \"\"hi\"\"\",,4102444801\n");
	CHECK(!std::filesystem::exists(directory.file("region-cache.csv.tmp")));
}

void test_saving_replaces_the_previous_file_and_creates_the_directory()
{
	DataDirectory				directory;
	const std::filesystem::path nested = directory.file("nested");
	fake_data_directory				   = nested.string();
	Cache cache;
	cache["1.1.1.1"] = {"A", "n1", 4102444800};
	save_region_cache(cache);
	CHECK(std::filesystem::exists(nested / "region-cache.csv"));

	cache.clear();
	cache["2.2.2.2"] = {"B", "n2", 4102444800};
	save_region_cache(cache);
	Cache loaded;
	load_region_cache(loaded);
	CHECK(loaded.size() == 1 && loaded.count("2.2.2.2") == 1);
}

void test_load_skips_expired_and_malformed_entries()
{
	DataDirectory	  directory;
	const std::string future = std::to_string(now_seconds() + 1000);
	const std::string past	 = std::to_string(now_seconds() - 1000);
	directory.write("region-cache.csv",
					"1.1.1.1,Good,GOOD," + future + "\n" + "2.2.2.2,Expired,EXP," + past + "\n" + "3.3.3.3,TooFew," + future + "\n" +
						"4.4.4.4,Too,Many,Fields," + future + "\n" + "5.5.5.5,BadExpiry,NAME,soon\n" + "6.6.6.6,\"Unterminated,NAME," + future + "\n" +
						",NoAddress,NAME," + future + "\n" + "\n" + "7.7.7.7,\"Quoted, with comma\",Q," + future + "\n");
	Cache cache;
	load_region_cache(cache);
	CHECK(cache.size() == 2);
	CHECK(cache.count("1.1.1.1") == 1 && cache["1.1.1.1"].label == "Good" && cache["1.1.1.1"].server_name == "GOOD");
	CHECK(cache.count("7.7.7.7") == 1 && cache["7.7.7.7"].label == "Quoted, with comma");
}

void test_load_merges_into_the_existing_cache()
{
	DataDirectory	  directory;
	const std::string future = std::to_string(now_seconds() + 1000);
	directory.write("region-cache.csv", "1.1.1.1,Fresh,F," + future + "\n");
	Cache cache;
	cache["1.1.1.1"] = {"Old", "O", 1};
	cache["2.2.2.2"] = {"Kept", "K", 2};
	load_region_cache(cache);
	CHECK(cache.size() == 2);
	CHECK(cache["1.1.1.1"].label == "Fresh");
	CHECK(cache["2.2.2.2"].label == "Kept");
}

void test_load_reads_the_legacy_tab_separated_file()
{
	DataDirectory	  directory;
	const std::string future = std::to_string(now_seconds() + 1000);
	directory.write("region-cache.tsv", "1.1.1.1\tIowa, United States\tIA-USC-1\t" + future + "\n2.2.2.2\tOld\tOLD\t1\nbroken line\n");
	Cache cache;
	load_region_cache(cache);
	CHECK(cache.size() == 1);
	CHECK(cache["1.1.1.1"].label == "Iowa, United States" && cache["1.1.1.1"].server_name == "IA-USC-1");

	// The csv file takes precedence once it exists.
	directory.write("region-cache.csv", "9.9.9.9,New,N," + future + "\n");
	Cache current;
	load_region_cache(current);
	CHECK(current.size() == 1 && current.count("9.9.9.9") == 1);
}

void test_missing_files_and_directories_are_tolerated()
{
	DataDirectory directory;
	Cache		  cache;
	cache["1.1.1.1"] = {"Kept", "K", 4102444800};
	load_region_cache(cache);
	CHECK(cache.size() == 1);

	// Without a per-user directory nothing is read or written.
	fake_data_directory.clear();
	load_region_cache(cache);
	save_region_cache(cache);
	CHECK(cache.size() == 1);
	CHECK(!std::filesystem::exists(directory.file("region-cache.csv")));
}

void test_rate_limited_requests_are_retried_after_the_advertised_delay()
{
	reset_fakes();
	scripted_responses					  = {{429, 0, ""}, {429, 3, "slow down"}, {200, 0, "{\"region\": \"Iowa\"}"}};
	const platform::HttpResponse response = https_get_until_not_rate_limited("ipapi.co", "/1.2.3.4/json/");
	CHECK(response.status == 200 && response.body == "{\"region\": \"Iowa\"}");
	CHECK(requests.size() == 3);
	for (const auto& request : requests)
		CHECK(request.first == "ipapi.co" && request.second == "/1.2.3.4/json/");
	// A missing Retry-After falls back to one second.
	CHECK(sleeps == (std::vector<uint32_t>{1000, 3000}));
}

void test_other_failures_are_returned_without_retrying()
{
	reset_fakes();
	scripted_responses = {{500, 0, "oops"}};
	CHECK(https_get_until_not_rate_limited("ipapi.co", "/json/").status == 500);
	CHECK(requests.size() == 1 && sleeps.empty());

	reset_fakes();
	CHECK(https_get_until_not_rate_limited("ipapi.co", "/json/").status == 0);
	CHECK(requests.size() == 1 && sleeps.empty());
}

void test_huge_retry_delays_are_clamped()
{
	reset_fakes();
	scripted_responses = {{429, 4294967, ""}, {429, 4294968, ""}, {429, UINT32_MAX, ""}, {200, 0, "done"}};
	CHECK(https_get_until_not_rate_limited("ipapi.co", "/json/").status == 200);
	CHECK(sleeps == (std::vector<uint32_t>{4294967000u, UINT32_MAX, UINT32_MAX}));
}
}  // namespace

int main(int argc, char** argv)
{
	logging::set_level(logging::level::error);
	static const test::TestCase cases[] = {
		{"private_addresses_are_not_public", test_private_addresses_are_not_public},
		{"public_addresses", test_public_addresses},
		{"extract_region_label", test_extract_region_label},
		{"build_server_name_splits_the_us_into_longitude_bands", test_build_server_name_splits_the_us_into_longitude_bands},
		{"build_server_name_for_other_regions", test_build_server_name_for_other_regions},
		{"build_server_name_falls_back_for_missing_fields", test_build_server_name_falls_back_for_missing_fields},
		{"build_server_name_uses_the_last_address_segment", test_build_server_name_uses_the_last_address_segment},
		{"cache_round_trip", test_cache_round_trip},
		{"cache_file_format", test_cache_file_format},
		{"saving_replaces_the_previous_file_and_creates_the_directory", test_saving_replaces_the_previous_file_and_creates_the_directory},
		{"load_skips_expired_and_malformed_entries", test_load_skips_expired_and_malformed_entries},
		{"load_merges_into_the_existing_cache", test_load_merges_into_the_existing_cache},
		{"load_reads_the_legacy_tab_separated_file", test_load_reads_the_legacy_tab_separated_file},
		{"missing_files_and_directories_are_tolerated", test_missing_files_and_directories_are_tolerated},
		{"rate_limited_requests_are_retried_after_the_advertised_delay", test_rate_limited_requests_are_retried_after_the_advertised_delay},
		{"other_failures_are_returned_without_retrying", test_other_failures_are_returned_without_retrying},
		{"huge_retry_delays_are_clamped", test_huge_retry_delays_are_clamped},
	};
	return test::run_tests("region", cases, argc, argv);
}
