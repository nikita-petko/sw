#ifdef _WIN32
#error "platform/posix/http.cc must not be built on Windows"
#endif

#include "platform.h"

#include <curl/curl.h>
#include <strings.h>
#include <cstdint>
#include <cstdlib>
#include <string>

namespace platform {
namespace {
size_t write_body(char* data, size_t size, size_t count, void* user)
{
	static_cast<std::string*>(user)->append(data, size * count);
	return size * count;
}

size_t read_header(char* data, size_t size, size_t count, void* user)
{
	const size_t	   length = size * count;
	const std::string  line(data, length);
	static const char  name[] = "retry-after:";
	if (line.size() > sizeof(name) - 1 && strncasecmp(line.c_str(), name, sizeof(name) - 1) == 0)
	{
		char*			   end	 = nullptr;
		const unsigned long value = std::strtoul(line.c_str() + sizeof(name) - 1, &end, 10);
		if (end != line.c_str() + sizeof(name) - 1)
			static_cast<HttpResponse*>(user)->retry_after_seconds = static_cast<uint32_t>(value);
	}
	return length;
}
}  // namespace

HttpResponse https_get(const std::string& host, const std::string& path)
{
	HttpResponse result;
	CURL*		 curl = curl_easy_init();
	if (!curl)
		return result;
	const std::string url = "https://" + host + path;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "lagsw/1.0");
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 9000L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 3000L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, read_header);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &result);
	if (curl_easy_perform(curl) == CURLE_OK)
	{
		long status = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
		result.status = static_cast<uint32_t>(status);
	}
	curl_easy_cleanup(curl);
	return result;
}

}  // namespace platform
