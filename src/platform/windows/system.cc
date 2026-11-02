#ifndef _WIN32
#	error "platform/windows/system.cc must only be built on Windows"
#endif

#include "platform.h"

#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
// The SDK's NDIS headers behind netioapi.h trip the strict warning level.
#pragma warning(push)
#pragma warning(disable : 4668)
#include <iphlpapi.h>
#include <netioapi.h>
#pragma warning(pop)
#include <objbase.h>
#include <timeapi.h>
#include <cstdio>
#include <cstdlib>

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

namespace {
	UINT original_output_code_page = 0;

	void restore_output_code_page()
	{
		if (original_output_code_page != 0)
			SetConsoleOutputCP(original_output_code_page);
	}
}  // namespace

void enable_terminal_colors()
{
	// The UI emits UTF-8 (block and box characters); a legacy OEM code page renders it as mojibake and breaks line widths.
	const UINT code_page = GetConsoleOutputCP();
	if (code_page != 0 && code_page != CP_UTF8 && SetConsoleOutputCP(CP_UTF8))
	{
		original_output_code_page = code_page;
		std::atexit(restore_output_code_page);
	}

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

int console_height()
{
	CONSOLE_SCREEN_BUFFER_INFO console_info;
	const HANDLE			   output = GetStdHandle(STD_OUTPUT_HANDLE);
	if (output == INVALID_HANDLE_VALUE || !GetConsoleScreenBufferInfo(output, &console_info))
		return 0;
	return console_info.srWindow.Bottom - console_info.srWindow.Top + 1;
}

SystemCounters system_counters()
{
	SystemCounters counters;
	FILETIME	   created, exited, kernel, user;
	if (GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
	{
		const auto to_100ns	 = [](const FILETIME& time) { return (static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime; };
		counters.cpu_seconds = static_cast<double>(to_100ns(kernel) + to_100ns(user)) / 1e7;
		counters.cpu_available = true;
	}
	// Interface counters are cumulative; loopback and interfaces that are down are left out.
	PMIB_IF_TABLE2 table = nullptr;
	if (GetIfTable2(&table) == NO_ERROR && table != nullptr)
	{
		for (ULONG index = 0; index < table->NumEntries; ++index)
		{
			const MIB_IF_ROW2& row = table->Table[index];
			if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK || row.OperStatus != IfOperStatusUp)
				continue;
			counters.nic_errors += row.InErrors + row.OutErrors;
			counters.nic_drops += row.InDiscards + row.OutDiscards;
			counters.nic_available = true;
		}
		FreeMibTable(table);
	}
	return counters;
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

}  // namespace platform
