#include "packet_engine_util.h"

#ifdef LAGSW_FEATURE_PCAP_FILES

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <string>
#include <system_error>

#include "log.h"
#include "platform.h"

LOG_DEFAULT_GROUP(logging::group::pcap)

bool pcap_files_enabled_for(const PcapFilesOptions& pcap_files, const ProfileOptions& profile)
{
	return pcap_files.enabled &&
		   std::any_of(pcap_files.enabled_for.begin(), pcap_files.enabled_for.end(), [&](const std::string& enabled_profile) {
			   return enabled_profile == "*" || enabled_profile == profile.name;
		   });
}

void write_pcap_u32(std::ofstream& file, uint32_t value)
{
	file.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

void write_pcap_u16(std::ofstream& file, uint16_t value)
{
	file.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

void start_pcap_capture(const PcapFilesOptions& pcap_files, int profile, const ProfileOptions& profile_options, PcapCapture& capture)
{
	const std::string guid = platform::generate_guid();
	if (guid.empty())
	{
		LOG_ERROR("profile #%d - %s PCAP capture: failed to generate a GUID", profile, profile_options.name.c_str());
		return;
	}
	capture.guid = guid;
	std::error_code error;
	std::filesystem::create_directories(pcap_files.output_dir, error);
	if (error)
	{
		LOG_ERROR("profile #%d - %s PCAP capture: failed to create directory %s: %s",
				  profile,
				  profile_options.name.c_str(),
				  pcap_files.output_dir.c_str(),
				  error.message().c_str());
		return;
	}
	capture.path = (std::filesystem::path(pcap_files.output_dir) / (capture.guid + ".pcap")).string();
	capture.file = std::make_unique<std::ofstream>(capture.path, std::ios::binary | std::ios::trunc);
	if (!*capture.file)
	{
		LOG_ERROR("profile #%d - %s PCAP capture: failed to open %s", profile, profile_options.name.c_str(), capture.path.c_str());
		capture.file.reset();
		return;
	}
	std::ofstream& file = *capture.file;
	write_pcap_u32(file, 0xa1b2c3d4);
	write_pcap_u16(file, 2);
	write_pcap_u16(file, 4);
	write_pcap_u32(file, 0);
	write_pcap_u32(file, 0);
	write_pcap_u32(file, 0xFFFF);
	write_pcap_u32(file, 101);
	if (!file)
	{
		LOG_ERROR("profile #%d - %s PCAP capture: failed to write header to %s", profile, profile_options.name.c_str(), capture.path.c_str());
		capture.file.reset();
	}
}

void record_pcap_packet(PcapCapture& capture, const uint8_t* packet_data, uint32_t length, const std::string& profile_label)
{
	std::ofstream& file			= *capture.file;
	const auto	   now			= std::chrono::system_clock::now().time_since_epoch();
	const auto	   seconds		= std::chrono::duration_cast<std::chrono::seconds>(now);
	const auto	   microseconds = std::chrono::duration_cast<std::chrono::microseconds>(now - seconds);
	write_pcap_u32(file, static_cast<uint32_t>(seconds.count()));
	write_pcap_u32(file, static_cast<uint32_t>(microseconds.count()));
	write_pcap_u32(file, length);
	write_pcap_u32(file, length);
	file.write(reinterpret_cast<const char*>(packet_data), length);
	if (!file)
	{
		LOG_ERROR("%s PCAP capture: failed to write %s", profile_label.c_str(), capture.path.c_str());
		capture.file.reset();
	}
}

#endif
