#ifdef _WIN32
#error "platform/posix/system.cc must not be built on Windows"
#endif

#include "platform.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

namespace platform {

uint64_t tick_ms()
{
	return static_cast<uint64_t>(
		std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

void sleep_ms(uint32_t milliseconds)
{
	std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

// the kernel timer is already fine grained enough
void begin_timer_resolution() {}
void end_timer_resolution() {}

std::string generate_guid()
{
	unsigned char bytes[16] = {};
	FILE*		  source	= std::fopen("/dev/urandom", "rb");
	if (!source)
		return {};
	const size_t read_count = std::fread(bytes, 1, sizeof(bytes), source);
	std::fclose(source);
	if (read_count != sizeof(bytes))
		return {};
	// RFC 4122 version 4
	bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0F) | 0x40);
	bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3F) | 0x80);
	char text[37] = {};
	std::snprintf(text,
				  sizeof(text),
				  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				  bytes[0],
				  bytes[1],
				  bytes[2],
				  bytes[3],
				  bytes[4],
				  bytes[5],
				  bytes[6],
				  bytes[7],
				  bytes[8],
				  bytes[9],
				  bytes[10],
				  bytes[11],
				  bytes[12],
				  bytes[13],
				  bytes[14],
				  bytes[15]);
	return text;
}

// terminals interpret ANSI escape sequences by default
void enable_terminal_colors() {}

int console_width()
{
	winsize size = {};
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) != 0)
		return 0;
	return size.ws_col;
}

bool acquire_single_instance()
{
	// the lock is released by the kernel when the process exits, so it never goes stale
	static int lock_fd = open("/tmp/lagsw.lock", O_RDWR | O_CREAT | O_CLOEXEC, 0666);
	if (lock_fd < 0)
		return true;
	return flock(lock_fd, LOCK_EX | LOCK_NB) == 0;
}

std::string data_directory()
{
	if (const char* data_home = std::getenv("XDG_DATA_HOME"); data_home && *data_home)
		return std::string(data_home) + "/lagsw";
	// under sudo the real user's home is the one worth caching into
	if (const char* home = std::getenv("HOME"); home && *home)
		return std::string(home) + "/.local/share/lagsw";
	return {};
}

void make_directory(const std::string& path)
{
	// parents are created too since ~/.local/share may not exist yet
	for (size_t position = path.find('/', 1); position != std::string::npos; position = path.find('/', position + 1))
		mkdir(path.substr(0, position).c_str(), 0755);
	mkdir(path.c_str(), 0755);
}

bool replace_file(const std::string& source, const std::string& destination)
{
	if (std::rename(source.c_str(), destination.c_str()) == 0)
		return true;
	std::remove(source.c_str());
	return false;
}

}  // namespace platform
