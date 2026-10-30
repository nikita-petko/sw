#include "nft_table.h"

#include <fcntl.h>
#include <spawn.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <mutex>

#include "log.h"

extern char** environ;

namespace nfq {
namespace {
constexpr const char* kTable = "inet lagsw";

std::mutex table_mutex;
bool	   table_created = false;

bool write_all(int fd, const std::string& data)
{
	size_t written = 0;
	while (written < data.size())
	{
		const ssize_t count = ::write(fd, data.data() + written, data.size() - written);
		if (count < 0)
		{
			if (errno == EINTR)
				continue;
			return false;
		}
		written += static_cast<size_t>(count);
	}
	return true;
}

std::string read_all(int fd)
{
	std::string output;
	char		buffer[512];
	::lseek(fd, 0, SEEK_SET);
	ssize_t count;
	while ((count = ::read(fd, buffer, sizeof(buffer))) > 0)
		output.append(buffer, static_cast<size_t>(count));
	return output;
}

std::string trim(std::string text)
{
	while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' '))
		text.pop_back();
	return text;
}

// The script and nft's stderr travel through memfds, which avoids pipe-buffer deadlocks and SIGPIPE.
bool run_nft_impl(const std::string& script, std::string& error)
{
	const int input	 = ::memfd_create("lagsw-nft-in", MFD_CLOEXEC);
	const int output = ::memfd_create("lagsw-nft-err", MFD_CLOEXEC);
	if (input < 0 || output < 0)
	{
		error = std::string("memfd_create failed: ") + std::strerror(errno);
		if (input >= 0)
			::close(input);
		if (output >= 0)
			::close(output);
		return false;
	}
	bool ok = write_all(input, script) && ::lseek(input, 0, SEEK_SET) == 0;
	if (!ok)
		error = "failed to prepare the nft script";
	else
	{
		posix_spawn_file_actions_t actions;
		posix_spawn_file_actions_init(&actions);
		posix_spawn_file_actions_adddup2(&actions, input, STDIN_FILENO);
		posix_spawn_file_actions_adddup2(&actions, output, STDERR_FILENO);
		posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
		char* const argv[] = {const_cast<char*>("nft"), const_cast<char*>("-f"), const_cast<char*>("-"), nullptr};
		pid_t		pid	   = 0;
		const int	rc	   = posix_spawnp(&pid, "nft", &actions, nullptr, argv, environ);
		posix_spawn_file_actions_destroy(&actions);
		if (rc != 0)
		{
			error = std::string("failed to run nft: ") + std::strerror(rc);
			ok	  = false;
		}
		else
		{
			int status = 0;
			while (::waitpid(pid, &status, 0) < 0 && errno == EINTR)
			{
			}
			if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			{
				error = trim(read_all(output));
				if (error.empty())
					error = "nft exited abnormally";
				ok = false;
			}
		}
	}
	::close(input);
	::close(output);
	return ok;
}

struct TableGuard
{
	~TableGuard() { remove_table(); }
};
}  // namespace

bool run_nft(const std::string& script, std::string& error)
{
	return run_nft_impl(script, error);
}

bool ensure_table(std::string& error)
{
	static TableGuard		   guard;
	std::lock_guard<std::mutex> lock(table_mutex);
	if (table_created)
		return true;
	// add + delete + add replaces a leftover table atomically and succeeds when none exists.
	const std::string script = std::string("add table ") + kTable + "\ndelete table " + kTable + "\nadd table " + kTable + "\n";
	if (!run_nft_impl(script, error))
		return false;
	table_created = true;
	return true;
}

bool table_present()
{
	{
		std::lock_guard<std::mutex> lock(table_mutex);
		if (!table_created)
			return true;
	}
	std::string error;
	return run_nft_impl(std::string("list table ") + kTable + "\n", error);
}

void remove_table()
{
	std::lock_guard<std::mutex> lock(table_mutex);
	if (!table_created)
		return;
	std::string error;
	if (!run_nft_impl(std::string("delete table ") + kTable + "\n", error))
		LOG_WARN("failed to remove the nftables table %s: %s", kTable, error.c_str());
	table_created = false;
}

bool add_channel_rules(uint32_t channel_id,
					   uint16_t queue_number,
					   int		priority,
					   const std::vector<CompiledRule>& rules,
					   ChannelChains& chains,
					   std::string& error)
{
	std::string script;
	for (const Hook hook : {Hook::input, Hook::output, Hook::forward})
	{
		bool used = false;
		for (const CompiledRule& rule : rules)
			used = used || rule.hook == hook;
		if (!used)
			continue;
		const std::string chain = "ch" + std::to_string(channel_id) + "_" + hook_name(hook);
		script += std::string("add chain ") + kTable + " " + chain + " { type filter hook " + hook_name(hook) + " priority " +
				  std::to_string(priority) + "; policy accept; }\n";
		for (const CompiledRule& rule : rules)
			if (rule.hook == hook)
				script += std::string("add rule ") + kTable + " " + chain + " " + rule.match + " queue flags bypass to " +
						  std::to_string(queue_number) + "\n";
		chains.names.push_back(chain);
	}
	if (script.empty())
		return true;
	if (run_nft_impl(script, error))
		return true;
	chains.names.clear();
	return false;
}

void remove_channel_rules(ChannelChains& chains)
{
	if (chains.names.empty())
		return;
	std::string script;
	for (const std::string& chain : chains.names)
		script += std::string("flush chain ") + kTable + " " + chain + "\ndelete chain " + kTable + " " + chain + "\n";
	std::string error;
	if (!run_nft_impl(script, error))
		LOG_DEBUG_GROUP(logging::group::backend, "failed to remove nftables chains: %s", error.c_str());
	chains.names.clear();
}
}  // namespace nfq
