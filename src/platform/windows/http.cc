#ifndef _WIN32
#error "platform/windows/http.cc must only be built on Windows"
#endif

#include "platform.h"

#include <windows.h>
#include <winhttp.h>
#include <cstdlib>
#include <exception>
#include <vector>

#include "log.h"

namespace platform {

HttpResponse https_get(const std::string& host, const std::string& path)
{
	const std::wstring wide_host(host.begin(), host.end());
	const std::wstring wide_path(path.begin(), path.end());
	HttpResponse	   result;
	HINTERNET		   session = WinHttpOpen(L"lagsw/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!session)
	{
		LOG_DEBUG("https_get: WinHttpOpen failed %lu", GetLastError());
		return result;
	}
	WinHttpSetTimeouts(session, 3000, 3000, 3000, 3000);
	if (HINTERNET connect = WinHttpConnect(session, wide_host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0))
	{
		LOG_DEBUG("https_get: connected to host");
		if (HINTERNET request = WinHttpOpenRequest(connect,
												   L"GET",
												   wide_path.c_str(),
												   nullptr,
												   WINHTTP_NO_REFERER,
												   WINHTTP_DEFAULT_ACCEPT_TYPES,
												   WINHTTP_FLAG_SECURE))
		{
			LOG_DEBUG("https_get: request opened, sending");
			if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
				WinHttpReceiveResponse(request, nullptr))
			{
				DWORD status	  = 0;
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

}  // namespace platform
