// Terminal formatting helpers of the net monitor: colors, units, padding and charts.
#include "net_monitor.h"

#ifdef LAGSW_FEATURE_NET_MONITOR

#	include <algorithm>
#	include <cmath>
#	include <cstdio>

#	include "internal.h"

namespace net_monitor_detail {

const char* rtt_color(double rtt_ms)
{
	return rtt_ms < 60 ? kGreen : rtt_ms < 120 ? kYellow : kRed;
}

const char* loss_color(double percent)
{
	return percent < 0.5 ? kGreen : percent < 2 ? kYellow : kRed;
}

const char* score_color(double score)
{
	return score >= 85 ? kGreen : score >= 60 ? kYellow : kRed;
}

std::string format_size(double bytes)
{
	char text[32];
	if (bytes >= 1024 * 1024)
		std::snprintf(text, sizeof(text), "%.2f MB", bytes / (1024 * 1024));
	else if (bytes >= 1024)
		std::snprintf(text, sizeof(text), "%.1f KB", bytes / 1024);
	else
		std::snprintf(text, sizeof(text), "%.0f B", bytes);
	return text;
}

std::string format_rate(double bytes_per_second)
{
	const double bits = bytes_per_second * 8;
	char		 text[32];
	if (bits >= 1e9)
		std::snprintf(text, sizeof(text), "%.2f Gbit/s", bits / 1e9);
	else if (bits >= 1e6)
		std::snprintf(text, sizeof(text), "%.2f Mbit/s", bits / 1e6);
	else if (bits >= 1e3)
		std::snprintf(text, sizeof(text), "%.1f kbit/s", bits / 1e3);
	else
		std::snprintf(text, sizeof(text), "%.0f bit/s", bits);
	return text;
}

std::string bar(double fraction, size_t width)
{
	const size_t filled = std::min(width, static_cast<size_t>(fraction * static_cast<double>(width) + 0.5));
	std::string	 out;
	for (size_t i = 0; i < width; ++i)
		out += i < filled ? "█" : "░";
	return out;
}

std::string format_age(double seconds)
{
	char			text[32];
	const long long total = static_cast<long long>(seconds);
	if (total < 60)
		std::snprintf(text, sizeof(text), "%llds", total);
	else if (total < 3600)
		std::snprintf(text, sizeof(text), "%lldm%02llds", total / 60, total % 60);
	else if (total < 86400)
		std::snprintf(text, sizeof(text), "%lldh%02lldm", total / 3600, total / 60 % 60);
	else
		std::snprintf(text, sizeof(text), "%lldd%02lldh", total / 86400, total / 3600 % 24);
	return text;
}

std::string format_ms(double value, bool available)
{
	if (!available)
		return "-";
	char text[32];
	if (value < 0)
		value = 0;
	if (value < 999.5)
		std::snprintf(text, sizeof(text), value < 10 ? "%.1f ms" : "%.0f ms", value);
	else if (value < 59950)
		std::snprintf(text, sizeof(text), "%.1f s", value / 1000);
	else
		return format_age(value / 1000);
	return text;
}

std::string format_ms_delta(double value)
{
	return std::string(value < 0 ? "-" : "+") + format_ms(std::fabs(value));
}

std::string format_clock(uint64_t seconds)
{
	char text[24];
	std::snprintf(text,
				  sizeof(text),
				  "%02llu:%02llu:%02llu",
				  static_cast<unsigned long long>(seconds / 3600),
				  static_cast<unsigned long long>(seconds / 60 % 60),
				  static_cast<unsigned long long>(seconds % 60));
	return text;
}

std::string pad(const std::string& text, size_t width)
{
	if (text.size() >= width)
		return text.substr(0, width);
	return text + std::string(width - text.size(), ' ');
}

std::string pad_left(const std::string& text, size_t width)
{
	if (text.size() >= width)
		return text.substr(0, width);
	return std::string(width - text.size(), ' ') + text;
}

std::string sparkline(const std::deque<double>& values, size_t width, double floor, const char* color)
{
	static const char* const blocks[] = {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
	const size_t			 count	  = std::min(width, values.size());
	double					 top	  = floor;
	for (size_t i = values.size() - count; i < values.size(); ++i)
		top = std::max(top, values[i]);
	std::string line = std::string(color);
	line.append(width - count, ' ');
	for (size_t i = values.size() - count; i < values.size(); ++i)
	{
		const double ratio = top > 0 ? values[i] / top : 0;
		line += values[i] <= 0 ? " " : blocks[std::min<size_t>(7, static_cast<size_t>(ratio * 7.999))];
	}
	return line + kReset;
}

std::vector<std::string> chart_rows(const std::deque<double>& values, size_t width, double floor, const char* color, size_t rows)
{
	if (rows <= 1)
		return {sparkline(values, width, floor, color)};
	static const char* const blocks[] = {" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
	const size_t			 count	  = std::min(width, values.size());
	double					 top	  = floor;
	for (size_t i = values.size() - count; i < values.size(); ++i)
		top = std::max(top, values[i]);
	std::vector<std::string> lines(rows, std::string(color));
	for (std::string& line : lines)
		line.append(width - count, ' ');
	for (size_t i = values.size() - count; i < values.size(); ++i)
	{
		const size_t levels =
			values[i] <= 0 ? 0 : std::max<size_t>(1, static_cast<size_t>(values[i] / top * static_cast<double>(rows * 8) + 0.5));
		for (size_t row = 0; row < rows; ++row)
		{
			const size_t from = (rows - 1 - row) * 8;
			lines[row] += blocks[levels <= from ? 0 : std::min<size_t>(8, levels - from)];
		}
	}
	for (std::string& line : lines)
		line += kReset;
	return lines;
}

std::vector<std::string> band_rows(const std::deque<double>& mean,
								   const std::deque<double>& low,
								   const std::deque<double>& high,
								   size_t					 width,
								   double					 floor,
								   const char*				 color,
								   size_t					 rows)
{
	if (rows <= 1 || low.size() != mean.size() || high.size() != mean.size())
		return chart_rows(mean, width, floor, color, rows);
	static const char* const blocks[] = {" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
	const size_t			 count	  = std::min(width, mean.size());
	const size_t			 first	  = mean.size() - count;
	double					 top	  = floor;
	for (size_t i = first; i < mean.size(); ++i)
		top = std::max({top, mean[i], high[i]});
	std::vector<std::string> lines(rows, std::string(color));
	for (std::string& line : lines)
		line.append(width - count, ' ');
	const auto level = [&](double value) {
		return value <= 0 ? size_t{0} : std::max<size_t>(1, static_cast<size_t>(value / top * static_cast<double>(rows * 8) + 0.5));
	};
	for (size_t i = first; i < mean.size(); ++i)
	{
		const size_t average = level(mean[i]);
		const size_t lowest	 = std::min(average, level(low[i]));
		const size_t highest = std::max(average, level(high[i]));
		for (size_t row = 0; row < rows; ++row)
		{
			const size_t from = (rows - 1 - row) * 8;
			if (average > from)
			{
				const size_t filled = std::min<size_t>(8, average - from);
				lines[row] += filled == 8 && from >= lowest ? "▓" : blocks[filled];
			}
			else if (highest > from)
				lines[row] += std::string(kDim) + "│" + color;
			else
				lines[row] += " ";
		}
	}
	for (std::string& line : lines)
		line += kReset;
	return lines;
}

std::string marker_row(const std::deque<double>& values, size_t width, const char* color)
{
	const size_t count = std::min(width, values.size());
	std::string	 line(width - count, ' ');
	for (size_t i = values.size() - count; i < values.size(); ++i)
		line += values[i] > 0 ? std::string(color) + "▄" + kReset : " ";
	return line;
}

}  // namespace net_monitor_detail

#endif	// LAGSW_FEATURE_NET_MONITOR
