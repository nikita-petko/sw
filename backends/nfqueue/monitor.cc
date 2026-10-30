#include "monitor.h"

#include <chrono>
#include <cstdio>
#include <map>

#include "log.h"
#include "nft_table.h"

LOG_DEFAULT_GROUP(logging::group::nfq_monitor)

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
bool							previous_table_ok = true;
bool							previous_readable = true;
std::map<uint16_t, bool>		previous_backlog;

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
		if (dropping)
			LOG_WARN("queue %u is dropping packets (kernel %llu -> %llu, user space %llu -> %llu)", static_cast<unsigned>(number),
					 static_cast<unsigned long long>(before->second.queue_dropped), static_cast<unsigned long long>(now.queue_dropped),
					 static_cast<unsigned long long>(before->second.user_dropped), static_cast<unsigned long long>(now.user_dropped));
		// Backlog is reported when it starts and when it clears, not on every sample
		bool& was_backlog = previous_backlog[number];
		if (backlog && !was_backlog)
			LOG_WARN("queue %u has %u packets waiting (threshold %u)", static_cast<unsigned>(number), now.queue_total, backlog_threshold);
		else if (!backlog && was_backlog)
			LOG_INFO("queue %u backlog cleared (%u waiting)", static_cast<unsigned>(number), now.queue_total);
		was_backlog = backlog;
		line += " q" + std::to_string(number) + " waiting " + std::to_string(now.queue_total) + " dropped " +
				std::to_string(now.queue_dropped) + "/" + std::to_string(now.user_dropped) + (dropping ? " (DROPPING)" : "") +
				(backlog ? " (BACKLOG)" : "") + " |";
		++shown;
	}
	previous = queues;
	if (table_ok != previous_table_ok)
	{
		if (table_ok)
			LOG_INFO("the nftables table is present again");
		else
			LOG_ERROR("the nftables table is missing; capture rules were removed");
		previous_table_ok = table_ok;
	}
	if (readable != previous_readable)
	{
		if (readable)
			LOG_INFO("NFQUEUE statistics are readable again");
		else
			LOG_WARN("NFQUEUE statistics are unavailable (%s cannot be read; is nfnetlink_queue loaded?)", kQueueStats);
		previous_readable = readable;
	}
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
