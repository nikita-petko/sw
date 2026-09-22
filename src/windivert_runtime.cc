#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdlib>
#include <filesystem>
#include <string>

#include "log.h"
#include "windivert_runtime.h"

namespace {
constexpr int kWinDivertDllResource = 101;
constexpr int kWinDivertSysResource = 102;

HMODULE				  windivert_module = nullptr;
std::filesystem::path runtime_directory;

decltype(&WinDivertOpen)				WinDivertOpen_fn				= nullptr;
decltype(&WinDivertRecv)				WinDivertRecv_fn				= nullptr;
decltype(&WinDivertSend)				WinDivertSend_fn				= nullptr;
decltype(&WinDivertShutdown)			WinDivertShutdown_fn			= nullptr;
decltype(&WinDivertClose)				WinDivertClose_fn				= nullptr;
decltype(&WinDivertSetParam)			WinDivertSetParam_fn			= nullptr;
decltype(&WinDivertHelperCompileFilter) WinDivertHelperCompileFilter_fn = nullptr;
decltype(&WinDivertHelperParsePacket)	WinDivertHelperParsePacket_fn	= nullptr;
decltype(&WinDivertHelperNtohl)			WinDivertHelperNtohl_fn			= nullptr;
decltype(&WinDivertHelperHtonl)			WinDivertHelperHtonl_fn			= nullptr;
decltype(&WinDivertHelperCalcChecksums) WinDivertHelperCalcChecksums_fn = nullptr;

bool extract_resource(int resource_id, const std::filesystem::path& path)
{
	HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(resource_id), RT_RCDATA);
	if (resource == nullptr)
	{
		LOG_ERROR("Could not find embedded WinDivert resource %d (error %lu)", resource_id, GetLastError());
		return false;
	}
	HGLOBAL		loaded = LoadResource(nullptr, resource);
	void*		data   = loaded == nullptr ? nullptr : LockResource(loaded);
	const DWORD size   = SizeofResource(nullptr, resource);
	if (data == nullptr || size == 0)
	{
		LOG_ERROR("Could not read embedded WinDivert resource %d (error %lu)", resource_id, GetLastError());
		return false;
	}

	HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file == INVALID_HANDLE_VALUE)
	{
		LOG_ERROR("Could not create embedded WinDivert file '%s' (error %lu)", path.string().c_str(), GetLastError());
		return false;
	}
	DWORD		written = 0;
	const bool	success = WriteFile(file, data, size, &written, nullptr) != FALSE && written == size;
	const DWORD error	= success ? ERROR_SUCCESS : GetLastError();
	CloseHandle(file);
	if (!success)
		LOG_ERROR("Could not write embedded WinDivert file '%s' (error %lu)", path.string().c_str(), error);
	else
		LOG_DEBUG("Extracted embedded WinDivert resource to '%s' (%lu bytes)", path.string().c_str(), size);
	return success;
}

void cleanup()
{
	if (windivert_module != nullptr)
	{
		FreeLibrary(windivert_module);
		windivert_module = nullptr;
	}
	if (!runtime_directory.empty())
	{
		std::error_code error;
		std::filesystem::remove_all(runtime_directory, error);
	}
}

bool load_functions()
{
#define LOAD_WINDIVERT_FUNCTION(name)                                                                  \
	name##_fn = reinterpret_cast<decltype(name##_fn)>(GetProcAddress(windivert_module, #name));        \
	if (name##_fn == nullptr)                                                                          \
	{                                                                                                  \
		LOG_ERROR("WinDivert.dll is missing exported function %s (error %lu)", #name, GetLastError()); \
		return false;                                                                                  \
	}
	LOAD_WINDIVERT_FUNCTION(WinDivertOpen);
	LOAD_WINDIVERT_FUNCTION(WinDivertRecv);
	LOAD_WINDIVERT_FUNCTION(WinDivertSend);
	LOAD_WINDIVERT_FUNCTION(WinDivertShutdown);
	LOAD_WINDIVERT_FUNCTION(WinDivertClose);
	LOAD_WINDIVERT_FUNCTION(WinDivertSetParam);
	LOAD_WINDIVERT_FUNCTION(WinDivertHelperCompileFilter);
	LOAD_WINDIVERT_FUNCTION(WinDivertHelperParsePacket);
	LOAD_WINDIVERT_FUNCTION(WinDivertHelperNtohl);
	LOAD_WINDIVERT_FUNCTION(WinDivertHelperHtonl);
	LOAD_WINDIVERT_FUNCTION(WinDivertHelperCalcChecksums);
#undef LOAD_WINDIVERT_FUNCTION
	return true;
}
}  // namespace

bool initialize_windivert()
{
	static bool initialized = false;
	static bool attempted	= false;
	if (attempted)
		return initialized;
	attempted = true;

	wchar_t temp_path[MAX_PATH] = {};
	if (GetTempPathW(static_cast<DWORD>(sizeof(temp_path) / sizeof(temp_path[0])), temp_path) == 0)
	{
		LOG_ERROR("Could not get temporary directory for embedded WinDivert (error %lu)", GetLastError());
		return false;
	}
	wchar_t temp_file[MAX_PATH] = {};
	if (GetTempFileNameW(temp_path, L"lsw", 0, temp_file) == 0)
	{
		LOG_ERROR("Could not create temporary path for embedded WinDivert (error %lu)", GetLastError());
		return false;
	}
	DeleteFileW(temp_file);
	runtime_directory = temp_file;
	if (!CreateDirectoryW(runtime_directory.c_str(), nullptr))
	{
		LOG_ERROR("Could not create embedded WinDivert directory '%s' (error %lu)", runtime_directory.string().c_str(), GetLastError());
		return false;
	}

	const std::filesystem::path dll_path = runtime_directory / L"WinDivert.dll";
	const std::filesystem::path sys_path = runtime_directory / L"WinDivert64.sys";
	if (!extract_resource(kWinDivertDllResource, dll_path) || !extract_resource(kWinDivertSysResource, sys_path))
	{
		LOG_ERROR("Could not extract embedded WinDivert runtime");
		cleanup();
		return false;
	}

	windivert_module = LoadLibraryW(dll_path.c_str());
	if (windivert_module == nullptr || !load_functions())
	{
		LOG_ERROR("Could not load embedded WinDivert.dll from '%s' (error %lu)", dll_path.string().c_str(), GetLastError());
		cleanup();
		return false;
	}
	std::atexit(cleanup);
	initialized = true;
	LOG_INFO("Embedded WinDivert runtime initialized");
	return true;
}

extern "C" HANDLE WinDivertOpen(const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags)
{
	return WinDivertOpen_fn(filter, layer, priority, flags);
}

extern "C" BOOL WinDivertRecv(HANDLE handle, VOID* packet, UINT packet_len, UINT* recv_len, WINDIVERT_ADDRESS* address)
{
	return WinDivertRecv_fn(handle, packet, packet_len, recv_len, address);
}

extern "C" BOOL WinDivertSend(HANDLE handle, const VOID* packet, UINT packet_len, UINT* send_len, const WINDIVERT_ADDRESS* address)
{
	return WinDivertSend_fn(handle, packet, packet_len, send_len, address);
}

extern "C" BOOL WinDivertShutdown(HANDLE handle, WINDIVERT_SHUTDOWN how)
{
	return WinDivertShutdown_fn(handle, how);
}

extern "C" BOOL WinDivertClose(HANDLE handle)
{
	return WinDivertClose_fn(handle);
}

extern "C" BOOL WinDivertSetParam(HANDLE handle, WINDIVERT_PARAM param, UINT64 value)
{
	return WinDivertSetParam_fn(handle, param, value);
}

extern "C" BOOL WinDivertHelperCompileFilter(const char*	 filter,
											 WINDIVERT_LAYER layer,
											 char*			 object,
											 UINT			 object_len,
											 const char**	 error,
											 UINT*			 error_position)
{
	return WinDivertHelperCompileFilter_fn(filter, layer, object, object_len, error, error_position);
}

extern "C" BOOL WinDivertHelperParsePacket(const VOID*			 packet,
										   UINT					 packet_len,
										   PWINDIVERT_IPHDR*	 pp_ip_hdr,
										   PWINDIVERT_IPV6HDR*	 pp_ipv6_hdr,
										   UINT8*				 p_protocol,
										   PWINDIVERT_ICMPHDR*	 pp_icmp_hdr,
										   PWINDIVERT_ICMPV6HDR* pp_icmpv6_hdr,
										   PWINDIVERT_TCPHDR*	 pp_tcp_hdr,
										   PWINDIVERT_UDPHDR*	 pp_udp_hdr,
										   PVOID*				 pp_data,
										   UINT*				 p_data_len,
										   PVOID*				 pp_next,
										   UINT*				 p_next_len)
{
	return WinDivertHelperParsePacket_fn(packet,
										 packet_len,
										 pp_ip_hdr,
										 pp_ipv6_hdr,
										 p_protocol,
										 pp_icmp_hdr,
										 pp_icmpv6_hdr,
										 pp_tcp_hdr,
										 pp_udp_hdr,
										 pp_data,
										 p_data_len,
										 pp_next,
										 p_next_len);
}

extern "C" UINT32 WinDivertHelperNtohl(UINT32 value)
{
	return WinDivertHelperNtohl_fn(value);
}

extern "C" UINT32 WinDivertHelperHtonl(UINT32 value)
{
	return WinDivertHelperHtonl_fn(value);
}

extern "C" BOOL WinDivertHelperCalcChecksums(VOID* packet, UINT packet_len, WINDIVERT_ADDRESS* address, UINT64 flags)
{
	return WinDivertHelperCalcChecksums_fn(packet, packet_len, address, flags);
}
