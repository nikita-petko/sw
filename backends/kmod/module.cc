#include "module.h"

#include <fcntl.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

#include "log.h"
#include "swdivert_abi.h"

extern char** environ;

LOG_DEFAULT_GROUP(logging::group::kmod)

namespace kmodb {

const char* const kDevicePath = "/dev/" SWDIVERT_DEVICE_NAME;

namespace {
	std::atomic<bool> loaded_here{false};

	// The standard places of the module tools: root's PATH often lacks the sbin directories
	std::string find_tool(const char* name)
	{
		for (const char* directory : {"/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/"})
		{
			const std::string path = std::string(directory) + name;
			if (::access(path.c_str(), X_OK) == 0)
				return path;
		}
		return {};
	}

	/// Runs a program without a shell. `output` receives what it wrote to stdout and stderr.
	bool run(const std::vector<std::string>& argv, std::string& output, int& exit_code)
	{
		output.clear();
		int pipes[2];
		if (::pipe2(pipes, O_CLOEXEC) != 0)
			return false;
		posix_spawn_file_actions_t actions;
		posix_spawn_file_actions_init(&actions);
		posix_spawn_file_actions_adddup2(&actions, pipes[1], STDOUT_FILENO);
		posix_spawn_file_actions_adddup2(&actions, pipes[1], STDERR_FILENO);
		posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
		std::vector<char*> args;
		for (const std::string& argument : argv)
			args.push_back(const_cast<char*>(argument.c_str()));
		args.push_back(nullptr);
		pid_t	  pid	= 0;
		const int error = ::posix_spawn(&pid, argv[0].c_str(), &actions, nullptr, args.data(), environ);
		posix_spawn_file_actions_destroy(&actions);
		::close(pipes[1]);
		if (error != 0)
		{
			::close(pipes[0]);
			output = std::strerror(error);
			return false;
		}
		char	buffer[512];
		ssize_t count;
		while ((count = ::read(pipes[0], buffer, sizeof(buffer))) > 0 || (count < 0 && errno == EINTR))
			if (count > 0 && output.size() < 2048)
				output.append(buffer, static_cast<size_t>(count));
		::close(pipes[0]);
		int status = 0;
		while (::waitpid(pid, &status, 0) < 0 && errno == EINTR)
		{
		}
		exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
		while (!output.empty() && (output.back() == '\n' || output.back() == ' '))
			output.pop_back();
		return true;
	}

	std::string executable_directory()
	{
		char		  path[4096];
		const ssize_t length = ::readlink("/proc/self/exe", path, sizeof(path) - 1);
		if (length <= 0)
			return {};
		path[length]	  = '\0';
		const char* slash = std::strrchr(path, '/');
		return slash ? std::string(path, static_cast<size_t>(slash - path)) : std::string();
	}

	/// The .ko of a development build: $LAGSW_KMOD_PATH, else swdivert.ko next to the executable.
	std::string module_file()
	{
		if (const char* given = std::getenv("LAGSW_KMOD_PATH"); given != nullptr && *given != '\0')
			return given;
		const std::string next_to_binary = executable_directory() + "/swdivert.ko";
		return ::access(next_to_binary.c_str(), R_OK) == 0 ? next_to_binary : std::string();
	}

	bool wait_for_device()
	{
		// udev creates the node a moment after the module registers its device
		for (int attempt = 0; attempt < 60; ++attempt)
		{
			if (::access(kDevicePath, F_OK) == 0)
				return true;
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}
		return false;
	}

	enum class Check
	{
		ok,
		missing,
		failed,
	};

	Check check_device(std::string& error)
	{
		const int fd = ::open(kDevicePath, O_RDWR | O_CLOEXEC);
		if (fd < 0)
		{
			if (errno == ENOENT)
				return Check::missing;
			error =
				std::string("cannot open ") + kDevicePath + ": " + std::strerror(errno) +
				(errno == EACCES || errno == EPERM ? " (the device needs root or a udev rule that grants access, and CAP_NET_ADMIN)" : "");
			return Check::failed;
		}
		uint32_t  version = 0;
		const int result  = ::ioctl(fd, SWDIVERT_IOC_VERSION, &version);
		const int saved	  = errno;
		::close(fd);
		if (result != 0)
		{
			error = std::string(kDevicePath) + " does not answer the version request: " + std::strerror(saved);
			return Check::failed;
		}
		if (version != SWDIVERT_ABI_VERSION)
		{
			error = "the loaded swdivert module speaks ABI " + std::to_string(version) + " but this lagsw build needs ABI " +
					std::to_string(SWDIVERT_ABI_VERSION) +
					"; unload the module (`rmmod swdivert`) and load the one that belongs to this build, or use the matching lagsw build";
			return Check::failed;
		}
		return Check::ok;
	}

	std::string load_instructions()
	{
		return "load it with `modprobe swdivert` (installed module) or `insmod path/to/swdivert.ko` (development build: xmake build "
			   "swdivert), "
			   "or run lagsw as root so that it can do that: it looks for swdivert.ko next to the executable and in $LAGSW_KMOD_PATH";
	}
}  // namespace

bool ensure_module(std::string& error)
{
	switch (check_device(error))
	{
		case Check::ok:
			LOG_DEBUG("swdivert module present (abi %d)", SWDIVERT_ABI_VERSION);
			return true;
		case Check::failed:
			return false;
		case Check::missing:
			break;
	}

	if (::geteuid() != 0)
	{
		error = std::string(kDevicePath) + " does not exist: the swdivert kernel module is not loaded, and only root can load it; " +
				load_instructions();
		return false;
	}

	std::string attempts;
	bool		loaded = false;
	std::string output;
	int			code = 0;
	if (const std::string modprobe = find_tool("modprobe"); !modprobe.empty())
	{
		if (run({modprobe, "swdivert"}, output, code) && code == 0)
		{
			loaded = true;
		}
		else
		{
			LOG_DEBUG("modprobe swdivert failed (exit %d): %s", code, output.c_str());
			attempts += "modprobe swdivert: " + (output.empty() ? std::string("failed") : output) + "; ";
		}
	}
	if (!loaded)
	{
		const std::string file	 = module_file();
		const std::string insmod = find_tool("insmod");
		if (file.empty())
		{
			attempts += "no swdivert.ko next to the executable and LAGSW_KMOD_PATH is not set; ";
		}
		else if (insmod.empty())
		{
			attempts += "insmod was not found; ";
		}
		else if (run({insmod, file}, output, code) && code == 0)
		{
			loaded = true;
		}
		else
		{
			LOG_DEBUG("insmod %s failed (exit %d): %s", file.c_str(), code, output.c_str());
			attempts += "insmod " + file + ": " + (output.empty() ? std::string("failed") : output) + "; ";
		}
	}
	if (!loaded)
	{
		error = "the swdivert kernel module is not loaded and loading it failed (" + attempts + "); " + load_instructions();
		return false;
	}
	loaded_here = true;
	if (!wait_for_device())
	{
		error = std::string("the swdivert module was loaded but ") + kDevicePath + " did not appear (is udev running?)";
		return false;
	}
	if (check_device(error) != Check::ok)
	{
		if (error.empty())
			error = std::string(kDevicePath) + " is not usable after loading the module";
		return false;
	}
	LOG_INFO("loaded the swdivert kernel module (abi %d)", SWDIVERT_ABI_VERSION);
	return true;
}

void unload_if_loaded_here()
{
	const char* wanted = std::getenv("LAGSW_KMOD_UNLOAD_ON_EXIT");
	if (!loaded_here || wanted == nullptr || *wanted == '\0' || std::strcmp(wanted, "0") == 0)
		return;
	const std::string rmmod = find_tool("rmmod");
	if (rmmod.empty())
		return;
	std::string output;
	int			code = 0;
	if (run({rmmod, "swdivert"}, output, code) && code == 0)
		LOG_INFO("unloaded the swdivert kernel module");
	else
		LOG_DEBUG("rmmod swdivert failed (exit %d): %s", code, output.c_str());
}

}  // namespace kmodb
