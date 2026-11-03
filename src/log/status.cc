#include <log.h>

#include <cstdio>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "internal.h"
#include "platform.h"

namespace logging_detail {
std::string status_line;
std::string status_right_line;
std::vector<std::string> extra_status_lines;
bool suspended = false;
std::vector<std::string> suspended_backlog;
std::string banner;
int banner_rows = 0;
int banner_columns = 0;

constexpr int min_banner_rows = 8;
std::string banner_text_at_right(int columns)
{
	const std::string shown = banner.size() > static_cast<size_t>(columns) ? banner.substr(0, static_cast<size_t>(columns)) : banner;
	return "\033[1;" + std::to_string(columns - static_cast<int>(shown.size()) + 1) + "H\033[90m" + shown + "\033[0m";
}
// Restores the scroll region when the console was resized (or `force`) and redraws the banner without moving the cursor.
std::string banner_sequence(bool force)
{
	if (banner.empty())
		return {};
	const int rows	  = platform::console_height();
	const int columns = platform::console_width();
	if (rows < min_banner_rows || columns <= 0)
		return {};
	std::string out = "\033" "7";
	if (force || rows != banner_rows || columns != banner_columns)
	{
		banner_rows	   = rows;
		banner_columns = columns;
		out += "\033[2;" + std::to_string(rows) + "r\033[1;1H\033[2K";
	}
	out += banner_text_at_right(columns) + "\033" "8";
	return out;
}
// Full-screen views own the whole screen, so the banner is drawn over their first row.
std::string banner_overlay()
{
	const int columns = platform::console_width();
	if (banner.empty() || platform::console_height() < min_banner_rows || columns <= 0)
		return {};
	return banner_text_at_right(columns);
}
void clear_status_line()
{
	if (status_line.empty())
		return;
	std::printf("\r\033[2K");
	// The extra lines sit below the cursor; wipe them and return to the main line.
	for (size_t i = 0; i < extra_status_lines.size(); ++i)
		std::printf("\033[B\033[2K");
	if (!extra_status_lines.empty())
		std::printf("\033[%zuA\r", extra_status_lines.size());
}
int console_width()
{
	return platform::console_width();
}
std::string format_status_line(const std::string& status, const std::string& right_status)
{
	const int width = console_width();
	if (width > 0 && !right_status.empty() && status.size() + right_status.size() <= static_cast<size_t>(width))
	{
		const size_t padding = static_cast<size_t>(width) - status.size() - right_status.size();
		return "\033[30;47m" + status + std::string(padding, ' ') + right_status + "\033[0m";
	}
	const size_t padding = width > 0 && status.size() < static_cast<size_t>(width) ? static_cast<size_t>(width) - status.size() : 0;
	return "\033[30;47m" + status + std::string(padding, ' ') + "\033[0m";
}

std::string format_extra_line(const std::string& line)
{
	const int		  width = console_width();
	const std::string shown = width > 0 && line.size() > static_cast<size_t>(width) ? line.substr(0, static_cast<size_t>(width)) : line;
	const size_t	  pad	= width > 0 && shown.size() < static_cast<size_t>(width) ? static_cast<size_t>(width) - shown.size() : 0;
	return "\033[30;47m" + shown + std::string(pad, ' ') + "\033[0m";
}
void print_status_line(const std::string& status, const std::string& right_status = {})
{
	std::printf("\r%s", format_status_line(status, right_status).c_str());
}

void print_status_block(const std::string& status, const std::string& right_status)
{
	print_status_line(status, right_status);
	if (extra_status_lines.empty())
		return;
	for (const std::string& line : extra_status_lines)
		std::printf("\n\r%s", format_extra_line(line).c_str());
	std::printf("\033[%zuA\r", extra_status_lines.size());
}
// Rows the status block takes at the bottom of a full-screen view; none when the console is too short to share.
int pinned_rows(int console_rows)
{
	if (status_line.empty() || console_rows <= 0)
		return 0;
	const int rows = 1 + static_cast<int>(extra_status_lines.size());
	return console_rows >= rows + 8 ? rows : 0;
}

std::string pinned_status_block(int console_rows)
{
	const int rows = pinned_rows(console_rows);
	if (rows == 0)
		return {};
	std::string out;
	int			row = console_rows - rows + 1;
	out += "\033[" + std::to_string(row++) + ";1H" + format_status_line(status_line, status_right_line);
	for (const std::string& line : extra_status_lines)
		out += "\033[" + std::to_string(row++) + ";1H" + format_extra_line(line);
	return out;
}

}

namespace logging {
using namespace logging_detail;
void set_status(const std::string& status)
{
	set_status(status, {});
}

void set_status(const std::string& status, const std::string& right_status)
{
	std::lock_guard lock(log_mutex);
	status_line		  = status;
	status_right_line = right_status;
	if (suspended)
		std::fputs(pinned_status_block(platform::console_height()).c_str(), stdout);
	else
	{
		std::fputs(banner_sequence(false).c_str(), stdout);
		print_status_block(status, right_status);
	}
	std::fflush(stdout);
}

void begin_capture()
{
	std::lock_guard lock(log_mutex);
	capturing = true;
	captured.clear();
}

std::vector<std::string> end_capture()
{
	std::lock_guard lock(log_mutex);
	capturing = false;
	return std::move(captured);
}

void set_extra_status(const std::vector<std::string>& lines)
{
	std::lock_guard lock(log_mutex);
	if (lines == extra_status_lines)
		return;
	// The block is redrawn by the next set_status(); wipe it first so a changed line count leaves nothing behind.
	if (!suspended && lines.size() != extra_status_lines.size())
		clear_status_line();
	extra_status_lines = lines;
	std::fflush(stdout);
}

void set_suspended(bool suspend)
{
	std::lock_guard lock(log_mutex);
	if (suspended == suspend)
		return;
	suspended = suspend;
	if (suspend)
		return;
	clear_status_line();
	std::fputs(banner_sequence(true).c_str(), stdout);
	for (const std::string& line : suspended_backlog)
		std::fputs(line.c_str(), stdout);
	suspended_backlog.clear();
	if (!status_line.empty())
		print_status_block(status_line, status_right_line);
	std::fflush(stdout);
}

void write_frame(const std::string& frame, int console_rows)
{
	std::lock_guard lock(log_mutex);
	std::fwrite(frame.data(), 1, frame.size(), stdout);
	std::fputs(banner_overlay().c_str(), stdout);
	std::fputs(pinned_status_block(console_rows).c_str(), stdout);
	std::fflush(stdout);
}

int pinned_status_rows(int console_rows)
{
	std::lock_guard lock(log_mutex);
	return pinned_rows(console_rows);
}

void clear_status()
{
	std::lock_guard lock(log_mutex);
	clear_status_line();
	extra_status_lines.clear();
	status_line.clear();
	status_right_line.clear();
	std::printf("\r\033[2K");
	std::fflush(stdout);
}

void set_banner(const std::string& text)
{
	std::lock_guard lock(log_mutex);
	if (platform::console_height() < min_banner_rows || platform::console_width() <= 0)
		return;
	banner = text;
	std::fputs("\033[2J\033[H", stdout);
	std::fputs(banner_sequence(true).c_str(), stdout);
	std::fputs("\033[2;1H", stdout);
	std::fflush(stdout);
}

void clear_banner()
{
	std::lock_guard lock(log_mutex);
	if (banner.empty())
		return;
	banner.clear();
	// Resetting the scroll region homes the cursor, so it is put back where it was.
	std::fputs("\033" "7\033[r\033" "8", stdout);
	std::fflush(stdout);
}

}  // namespace logging
