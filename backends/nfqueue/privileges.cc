#include "privileges.h"

#include <dirent.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstring>

#include "log.h"

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT			1
#define PR_CAP_AMBIENT_IS_SET	1
#endif

namespace nfq {
namespace {
bool has_effective_capability(int capability)
{
	__user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
	__user_cap_data_struct	 data[_LINUX_CAPABILITY_U32S_3] = {};
	if (::syscall(SYS_capget, &header, data) != 0)
		return false;
	return (data[capability / 32].effective >> (capability % 32)) & 1;
}

bool has_ambient_capability(int capability)
{
	return ::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0) == 1;
}

/// Hotkeys come from evdev; reading /dev/input needs root or the `input` group.
void warn_if_keyboards_unreadable()
{
	DIR* directory = opendir("/dev/input");
	if (!directory)
		return;
	bool found	  = false;
	bool readable = false;
	while (const dirent* entry = readdir(directory))
	{
		if (std::strncmp(entry->d_name, "event", 5) != 0)
			continue;
		found = true;
		if (::access((std::string("/dev/input/") + entry->d_name).c_str(), R_OK) == 0)
		{
			readable = true;
			break;
		}
	}
	closedir(directory);
	if (found && !readable)
		LOG_WARN("Cannot read /dev/input/event*, so hotkeys will not work. Run as root or add your user to the 'input' group.");
}
}  // namespace

bool check_privileges(std::string& error)
{
	if (!has_effective_capability(CAP_NET_ADMIN))
	{
		error = "lagsw needs CAP_NET_ADMIN to capture packets. Run it as root (for example `sudo ./lagsw ...` or scripts/bootstrap.sh).";
		return false;
	}
	// Rules are installed by spawning `nft`, which does not inherit file capabilities.
	if (::geteuid() != 0 && !has_ambient_capability(CAP_NET_ADMIN))
	{
		error = "lagsw has CAP_NET_ADMIN but the `nft` helper it spawns would not inherit it. Run as root or grant the capability as an ambient capability.";
		return false;
	}
	warn_if_keyboards_unreadable();
	return true;
}
}  // namespace nfq
