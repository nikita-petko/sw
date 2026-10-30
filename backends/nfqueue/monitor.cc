#include "monitor.h"

#include <chrono>
#include <cstdio>
#include <map>

#include "nft_table.h"

namespace nfq {
namespace {
constexpr const char* kQueueStats = "/proc/net/netfilter/nfnetlink_queue";

struct QueueSample
{
	uint32_t queue_total	 = 0;
	uint64_t queue_dropped = 0;
	uint64_t user_dropped	 = 0;
};

/// Columns: queue, peer portid, queue_total, copy_mode, copy_range, queue_dropped, user_dropped, id_sequence, 1.
/// Returns false when the file cannot be read (nfnetlink_queue not loaded).
bool read_queues(std::map<uint16_t, QueueSample>& queues)
{
	std::FILE* file = std::fopen(kQueueStats, "r");
	if (!file)
		return false;
	unsigned queue, portid, total, mode, range, id_sequence, one;
	unsigned long long queue_dropped, user_dropped;
	while (std::fscanf(file, "%u %u %u %u %u %llu %llu %u %u", &queue, &portid, &total, &mode, &range, &queue_dropped, &user_dropped,
					   &id_sequence, &one) == 9)
		queues[static_cast<uint16_t>(queue)] = {total, queue_dropped, user_dropped};
	std::fclose(file);
	return true;
}

std::map<uint16_t, QueueSample> previous;
std::string						cached;
std::chrono::steady_clock::time_point last_sample;
bool							sampled = false;

std::string sample(uint16_t first_queue, uint32_t queue_count, uint32_t backlog_threshold)
{
	std::map<uint16_t, QueueSample> queues;
	const bool						readable = read_queues(queues);
	const bool						table_ok = table_present();

	std::string line = "nfq:";
	bool		alert = !table_ok;
	size_t		shown = 0;
	for (uint32_t i = 0; i < queue_count; ++i)
	{
		const uint16_t number = static_cast<uint16_t>(first_queue + i);
		const auto	   found  = queues.find(number);
		if (found == queues.end())
			continue;
		const QueueSample& now		 = found->second;
		const auto		   before	 = previous.find(number);
		const bool		   dropping = before != previous.end() && (now.queue_dropped > before->second.queue_dropped || now.user_dropped > before->second.user_dropped);
		const bool		   backlog	 = now.queue_total >= backlog_threshold;
		alert = alert || dropping || backlog;
		line += " q" + std::to_string(number) + " waiting " + std::to_string(now.queue_total) + " dropped " +
				std::to_string(now.queue_dropped) + "/" + std::to_string(now.user_dropped) + (dropping ? " (DROPPING)" : "") +
				(backlog ? " (BACKLOG)" : "") + " |";
		++shown;
	}
	previous = queues;
	if (!readable)
		line += " queue stats unavailable |";
	else if (shown == 0)
		line += " no queues bound |";
	line += table_ok ? " table ok" : " TABLE MISSING (capture rules were removed!)";
	return alert ? line + " [!]" : line;
}
}  // namespace

std::string monitor_status(uint16_t first_queue, uint32_t queue_count, uint64_t interval_ms, uint32_t backlog_threshold)
{
	const auto now = std::chrono::steady_clock::now();
	if (!sampled || now - last_sample >= std::chrono::milliseconds(interval_ms))
	{
		cached		= sample(first_queue, queue_count, backlog_threshold);
		last_sample = now;
		sampled		= true;
	}
	return cached;
}

}  // namespace nfq
