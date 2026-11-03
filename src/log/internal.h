#ifndef LOG_INTERNAL_H_
#define LOG_INTERNAL_H_

#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <log.h>

namespace logging_detail {
constexpr size_t max_groups = 64;
constexpr size_t max_suspended_backlog = 500;
struct GroupCounters
{
	std::atomic<std::uint64_t> by_level[4];
	std::atomic<std::uint64_t> muted;
};

extern logging::level minimum_level;
extern std::mutex log_mutex;
extern std::mutex group_mutex;
extern std::atomic<bool> show_groups;
extern std::vector<std::pair<std::string, bool>> group_rules;
extern std::atomic<bool> groups_configured;
extern GroupCounters group_counters[max_groups];
extern std::string status_line;
extern std::string status_right_line;
extern std::vector<std::string> extra_status_lines;
extern bool suspended;
extern std::vector<std::string> suspended_backlog;
extern bool capturing;
extern std::vector<std::string> captured;
extern std::string banner;
extern int banner_rows;
extern int banner_columns;

void clear_status_line();
std::string banner_sequence(bool force);
std::string banner_overlay();
void print_status_block(const std::string& status, const std::string& right_status);
}

#endif
