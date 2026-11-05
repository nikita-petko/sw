#include "module.h"

#include <fcntl.h>
#include <linux/capability.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <thread>
#include <vector>

#include "../linux_shared/privileges.h"
#include "embedded.h"
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
		denied,	 ///< the node exists and this process may not open it (EACCES): udev has not opened it to a group, or never will
		failed,
	};

	Check check_device(std::string& error)
	{
		const int fd = ::open(kDevicePath, O_RDWR | O_CLOEXEC);
		if (fd < 0)
		{
			if (errno == ENOENT)
				return Check::missing;
			if (errno == EACCES)
			{
				error = std::string("cannot open ") + kDevicePath +
						": Permission denied. The device node is root-only until a udev rule opens it to a group: install the rule and add "
						"your user "
						"to that group (scripts/package/linux/setup_kmod_access.sh install --user <name>, which ships next to lagsw; log "
						"in again "
						"afterwards), or run lagsw as root. Opening it also needs CAP_NET_ADMIN";
				return Check::denied;
			}
			error = std::string("cannot open ") + kDevicePath + ": " + std::strerror(errno) +
					(errno == EPERM ? " (opening the device needs CAP_NET_ADMIN)" : "");
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
			   "swdivert), or let lagsw do it: it needs root or CAP_SYS_MODULE, and loads the module embedded in the executable, "
			   "$LAGSW_KMOD_PATH, an installed module, or swdivert.ko next to the executable, in that order";
	}

	std::string read_small_file(const char* path)
	{
		std::ifstream file(path);
		std::string	  text;
		std::getline(file, text);
		return text;
	}

	/// What init_module(2) failing with `code` means for a module that is built for one kernel and may have to be signed.
	std::string explain_load_failure(int code)
	{
		switch (code)
		{
			case EPERM:
				if (read_small_file("/proc/sys/kernel/modules_disabled") == "1")
					return "kernel.modules_disabled is set, so no module can be loaded until the next boot";
				if (const std::string lockdown = read_small_file("/sys/kernel/security/lockdown");
					lockdown.find("[none]") == std::string::npos && !lockdown.empty())
					return "kernel lockdown is on (" + lockdown +
						   "), which only lets signed modules load; this process may also lack CAP_SYS_MODULE";
				return "not permitted: loading a module needs CAP_SYS_MODULE (root has it; or `setcap cap_net_admin,cap_sys_module+ep "
					   "lagsw`)";
			case ENOEXEC:
				return "the kernel does not accept this module (damaged, or built for a kernel with other symbol versions or options); "
					   "`dmesg | tail` says which";
			case ENODATA:
				return "the module is not signed and this kernel only loads signed modules (Secure Boot or module.sig_enforce)";
			case ENOKEY:
				return "the module is signed with a key this kernel does not trust (enroll the certificate, for example with `mokutil "
					   "--import`)";
			case EKEYREJECTED:
				return "the module's signature was rejected (wrong key or damaged module)";
			case EBUSY:
				return "the kernel is busy with a module of the same name";
			case ENOMEM:
				return "out of memory";
			case EINVAL:
				return "the kernel rejected the image (not a module, or a damaged one); `dmesg | tail` says why";
			default:
				return std::strerror(code);
		}
	}

	bool read_whole_file(const std::string& path, std::vector<uint8_t>& bytes, std::string& error)
	{
		std::ifstream file(path, std::ios::binary);
		if (!file)
		{
			error = "cannot read " + path + ": " + std::strerror(errno);
			return false;
		}
		bytes.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
		return true;
	}

	/// Loads a .ko given by path, in-process when it is a plain module (no helper program, so CAP_SYS_MODULE is enough), by `insmod`
	/// when it is compressed.
	bool load_file(const std::string& path, std::string& attempts, bool& already)
	{
		auto ends_with = [&](const char* suffix) {
			const size_t length = std::strlen(suffix);
			return path.size() >= length && path.compare(path.size() - length, length, suffix) == 0;
		};
		const bool	compressed = ends_with(".xz") || ends_with(".gz") || ends_with(".zst");
		std::string error;
		if (!compressed)
		{
			std::vector<uint8_t> bytes;
			if (!read_whole_file(path, bytes, error))
			{
				attempts += error + "; ";
				return false;
			}
			switch (load_module_image(bytes.data(), bytes.size(), error))
			{
				case LoadStatus::loaded:
					return true;
				case LoadStatus::already_loaded:
					already = true;
					return true;
				case LoadStatus::failed:
					attempts += path + ": " + error + "; ";
					return false;
			}
		}
		const std::string insmod = find_tool("insmod");
		std::string		  output;
		int				  code = 0;
		if (insmod.empty() || ::geteuid() != 0)
		{
			attempts += path + " is compressed and needs `insmod` run by root; ";
			return false;
		}
		if (run({insmod, path}, output, code) && code == 0)
			return true;
		attempts += "insmod " + path + ": " + (output.empty() ? std::string("failed") : output) + "; ";
		return false;
	}
}  // namespace

std::string kernel_release()
{
	utsname name = {};
	return ::uname(&name) == 0 ? std::string(name.release) : std::string();
}

LoadStatus load_module_image(const uint8_t* data, size_t size, std::string& error)
{
	if (::syscall(SYS_init_module, data, static_cast<unsigned long>(size), "") == 0)
		return LoadStatus::loaded;
	const int code = errno;
	if (code == EEXIST)
		return LoadStatus::already_loaded;
	error = explain_load_failure(code);
	if (code == ENOEXEC)
	{
		// The kernel's one answer for "not a module" and "not this kernel's module": the image itself can tell them apart
		const std::string built_for = image_release(data, size);
		if (built_for.empty())
			error = "this is not a kernel module (no version magic in it, or it is cut short); the kernel refused it";
		else if (built_for != kernel_release())
			error = "this module was built for kernel " + built_for + ", not for the running kernel " + kernel_release() +
					" (a module is built for one kernel: rebuild it against this one); `dmesg | tail` has the kernel's message";
	}
	return LoadStatus::failed;
}

bool ensure_module(std::string& error)
{
	switch (check_device(error))
	{
		case Check::ok:
			LOG_DEBUG("swdivert module present (abi %d)", SWDIVERT_ABI_VERSION);
			return true;
		case Check::failed:
		case Check::denied:
			return false;
		case Check::missing:
			break;
	}

	const bool root = ::geteuid() == 0;
	if (!root && !linux_shared::has_capability(CAP_SYS_MODULE))
	{
		error = std::string(kDevicePath) +
				" does not exist: the swdivert kernel module is not loaded, and loading a module needs root or "
				"CAP_SYS_MODULE (`sudo setcap cap_net_admin,cap_sys_module+ep lagsw`); " +
				load_instructions();
		return false;
	}

	std::string attempts;
	std::string source;
	bool		loaded	= false;
	bool		already = false;

	// 1. A module named explicitly: a development build, or one the user wants to be used instead of what is embedded. It is used alone: a
	// path that does not work is a mistake to report, not something to paper over with another module
	const char* given		  = std::getenv("LAGSW_KMOD_PATH");
	const bool	explicit_path = given != nullptr && *given != '\0';
	if (explicit_path)
	{
		loaded = load_file(given, attempts, already);
		source = given;
	}

	// 2. The module embedded in this executable for the running kernel, loaded from memory
	if (!loaded && !explicit_path)
	{
		std::string					   why_not;
		const std::vector<ModuleImage> images = embedded_images();
		const ModuleImage*			   image  = select_image(images, kernel_release(), why_not);
		if (image == nullptr)
		{
			attempts += why_not + "; ";
		}
		else
		{
			std::string load_error;
			switch (load_module_image(image->data, image->size, load_error))
			{
				case LoadStatus::loaded:
					loaded = true;
					break;
				case LoadStatus::already_loaded:
					loaded	= true;
					already = true;
					break;
				case LoadStatus::failed:
					LOG_DEBUG("loading the embedded swdivert module failed: %s", load_error.c_str());
					attempts += "embedded module: " + load_error + "; ";
					break;
			}
			source = "the embedded module for kernel " + kernel_release();
		}
	}

	// 3. An installed module (a distribution package or DKMS), whose signing the system already took care of
	if (!loaded && !explicit_path && root)
	{
		std::string output;
		int			code = 0;
		if (const std::string modprobe = find_tool("modprobe"); !modprobe.empty())
		{
			if (run({modprobe, "swdivert"}, output, code) && code == 0)
			{
				loaded = true;
				source = "an installed module";
			}
			else
			{
				LOG_DEBUG("modprobe swdivert failed (exit %d): %s", code, output.c_str());
				attempts += "modprobe swdivert: " + (output.empty() ? std::string("failed") : output) + "; ";
			}
		}
	}

	// 4. swdivert.ko next to the executable
	if (!loaded && !explicit_path)
	{
		const std::string next_to_binary = executable_directory() + "/swdivert.ko";
		if (::access(next_to_binary.c_str(), R_OK) == 0)
		{
			loaded = load_file(next_to_binary, attempts, already);
			source = next_to_binary;
		}
		else
		{
			attempts += "no swdivert.ko next to the executable; ";
		}
	}

	if (!loaded)
	{
		error = "the swdivert kernel module is not loaded and loading it failed (" + attempts + "); " + load_instructions();
		return false;
	}
	// A module somebody else loaded is theirs: only what this process loaded is ever unloaded
	loaded_here = !already;
	if (!wait_for_device())
	{
		error = std::string("the swdivert module was loaded but ") + kDevicePath + " did not appear (is udev running?)";
		return false;
	}
	// udev gives the node its group and mode a moment after the kernel created it root-only (0600): for a user who only gets in through the
	// rule, the first attempts can be refused. Waiting for it is bounded, and after that the refusal is real.
	Check state = check_device(error);
	for (int attempt = 0; state == Check::denied && attempt < 40; ++attempt)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
		state = check_device(error);
	}
	if (state != Check::ok)
	{
		if (error.empty())
			error = std::string(kDevicePath) + " is not usable after loading the module";
		return false;
	}
	LOG_INFO("%s the swdivert kernel module (abi %d) from %s", already ? "found" : "loaded", SWDIVERT_ABI_VERSION, source.c_str());
	return true;
}

void unload_if_loaded_here()
{
	const char* wanted = std::getenv("LAGSW_KMOD_UNLOAD_ON_EXIT");
	if (!loaded_here || wanted == nullptr || *wanted == '\0' || std::strcmp(wanted, "0") == 0)
		return;
	// O_NONBLOCK: a module that is still in use is refused at once instead of waited for
	if (::syscall(SYS_delete_module, SWDIVERT_DEVICE_NAME, O_NONBLOCK) == 0)
		LOG_INFO("unloaded the swdivert kernel module");
	else
		LOG_DEBUG("unloading the swdivert module failed: %s", std::strerror(errno));
}

}  // namespace kmodb
