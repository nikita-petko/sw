#include "config_tui.h"

#ifdef LAGSW_FEATURE_CONFIG_TUI

#	include <algorithm>
#	include <chrono>
#	include <ctime>
#	include <filesystem>
#	include <fstream>
#	include <system_error>

namespace config_tui {
namespace {
	namespace fs = std::filesystem;

	std::string quote(const std::string& value)
	{
		std::string quoted = "\"";
		for (const char c : value)
		{
			if (c == '"' || c == '\\')
				quoted += '\\';
			quoted += c;
		}
		return quoted + '"';
	}

	std::string unquote(const std::string& value)
	{
		if (value.size() < 2 || value.front() != '"' || value.back() != '"')
			return value;
		std::string result;
		for (size_t i = 1; i + 1 < value.size(); ++i)
		{
			if (value[i] == '\\' && i + 2 < value.size())
				++i;
			result += value[i];
		}
		return result;
	}

	std::string trim(const std::string& value)
	{
		const size_t begin = value.find_first_not_of(" \t\r");
		if (begin == std::string::npos)
			return {};
		return value.substr(begin, value.find_last_not_of(" \t\r") - begin + 1);
	}
}  // namespace

FileStatus probe_file(const std::string& path, const Validator& validate)
{
	std::error_code error;
	if (!fs::is_regular_file(path, error))
		return {FileState::missing, "not found"};
	{
		std::ifstream file(path, std::ios::binary);
		if (!file)
			return {FileState::unreadable, "cannot be opened (permission denied?)"};
	}
	const std::string complaint = validate ? validate(path) : std::string();
	if (!complaint.empty())
		return {FileState::unreadable, complaint};
	return {};
}

std::string recent_files_path(const std::string& config_directory)
{
	if (config_directory.empty())
		return {};
	return (fs::path(config_directory) / "recent.yml").string();
}

std::vector<RecentEntry> load_recent(const std::string& file)
{
	std::vector<RecentEntry> entries;
	if (file.empty())
		return entries;
	std::ifstream input(file);
	std::string	  line;
	bool		  header = false;
	while (std::getline(input, line))
	{
		const std::string text = trim(line);
		if (text.empty() || text[0] == '#')
			continue;
		if (!header)
		{
			// anything but the `recent:` list means the file is not ours
			if (text != "recent:")
				return {};
			header = true;
			continue;
		}
		if (text.rfind("- path:", 0) == 0)
			entries.push_back({unquote(trim(text.substr(7))), {}});
		else if (text.rfind("last_opened:", 0) == 0 && !entries.empty())
			entries.back().last_opened = unquote(trim(text.substr(12)));
	}
	entries.erase(std::remove_if(entries.begin(), entries.end(), [](const RecentEntry& entry) { return entry.path.empty(); }), entries.end());
	if (entries.size() > kMaxRecent)
		entries.resize(kMaxRecent);
	return entries;
}

bool save_recent(const std::string& file, const std::vector<RecentEntry>& entries)
{
	if (file.empty())
		return false;
	std::error_code error;
	fs::create_directories(fs::path(file).parent_path(), error);
	const std::string temporary = file + ".tmp";
	{
		std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
		if (!output)
			return false;
		output << "recent:\n";
		for (const RecentEntry& entry : entries)
		{
			output << "  - path: " << quote(entry.path) << "\n";
			if (!entry.last_opened.empty())
				output << "    last_opened: " << entry.last_opened << "\n";
		}
		if (!output.good())
		{
			output.close();
			fs::remove(temporary, error);
			return false;
		}
	}
	fs::rename(temporary, file, error);
	if (error)
	{
		fs::remove(temporary, error);
		return false;
	}
	return true;
}

void add_recent(std::vector<RecentEntry>& entries, const std::string& path, const std::string& timestamp)
{
	entries.erase(std::remove_if(entries.begin(), entries.end(), [&](const RecentEntry& entry) { return entry.path == path; }), entries.end());
	entries.insert(entries.begin(), {path, timestamp});
	if (entries.size() > kMaxRecent)
		entries.resize(kMaxRecent);
}

std::string absolute_path(const std::string& path)
{
	std::error_code error;
	const fs::path	absolute = fs::absolute(path, error);
	return error ? path : absolute.lexically_normal().string();
}

std::string utc_timestamp()
{
	const std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	std::tm			  utc {};
#	ifdef _WIN32
	gmtime_s(&utc, &now);
#	else
	gmtime_r(&now, &utc);
#	endif
	char buffer[32];
	std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc);
	return buffer;
}

}  // namespace config_tui

#endif
