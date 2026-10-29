#ifndef _WIN32
#error "platform_windows.cc must only be built on Windows"
#endif

#include "platform.h"

#include <windows.h>
#include <winhttp.h>
#include <conio.h>
#include <objbase.h>
#include <timeapi.h>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <vector>

#include "log.h"

namespace platform {

uint64_t tick_ms()
{
	return GetTickCount64();
}

void sleep_ms(uint32_t milliseconds)
{
	Sleep(milliseconds);
}

void begin_timer_resolution()
{
	timeBeginPeriod(1);
}

void end_timer_resolution()
{
	timeEndPeriod(1);
}

std::string generate_guid()
{
	GUID guid = {};
	if (FAILED(CoCreateGuid(&guid)))
		return {};
	char text[37] = {};
	std::snprintf(text,
				  sizeof(text),
				  "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				  static_cast<unsigned long>(guid.Data1),
				  guid.Data2,
				  guid.Data3,
				  guid.Data4[0],
				  guid.Data4[1],
				  guid.Data4[2],
				  guid.Data4[3],
				  guid.Data4[4],
				  guid.Data4[5],
				  guid.Data4[6],
				  guid.Data4[7]);
	return text;
}

void ignore_interrupt()
{
	SetConsoleCtrlHandler(nullptr, TRUE);
}

void enable_terminal_colors()
{
	HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD  mode	  = 0;
	if (output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode))
		SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

int console_width()
{
	CONSOLE_SCREEN_BUFFER_INFO console_info;
	const HANDLE			   output = GetStdHandle(STD_OUTPUT_HANDLE);
	if (output == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(output, &console_info))
		return 0;
	return console_info.srWindow.Right - console_info.srWindow.Left + 1;
}

bool acquire_single_instance()
{
	// the handle is intentionally never closed; the mutex lives until the process exits
	static const HANDLE mutex = CreateMutexA(nullptr, TRUE, "Global\\lagsw_single_instance");
	if (!mutex)
		return true;
	return GetLastError() != ERROR_ALREADY_EXISTS;
}

std::string data_directory()
{
	const char* local_app_data = std::getenv("LOCALAPPDATA");
	if (!local_app_data || *local_app_data == '\0')
		return {};
	return std::string(local_app_data) + "\\lagsw";
}

void make_directory(const std::string& path)
{
	CreateDirectoryA(path.c_str(), nullptr);
}

bool replace_file(const std::string& source, const std::string& destination)
{
	if (MoveFileExA(source.c_str(), destination.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		return true;
	DeleteFileA(source.c_str());
	return false;
}

int read_key()
{
	if (!_kbhit())
		return key::none;
	const int value = _getch();
	if (value != 0 && value != 0xE0)
		return value;
	switch (_getch())
	{
		case 0x4B:
			return key::left;
		case 0x4D:
			return key::right;
		case 0x49:
			return key::page_up;
		case 0x51:
			return key::page_down;
	}
	return key::none;
}

bool is_key_held(int key)
{
	return (::GetAsyncKeyState(key) & 0x8000) != 0;
}

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
