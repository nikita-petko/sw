// End-to-end check of the kernel-module build: talks to a loaded swdivert_echo module. Needs root and the module, so it is run by
// scripts/test_kmod_echo.sh rather than `xmake test`.
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "swdivert_echo_abi.h"

namespace {
int g_failures = 0;

void check(bool ok, const char* what)
{
	std::printf("%s %s\n", ok ? "ok  " : "FAIL", what);
	if (!ok)
		++g_failures;
}

bool write_all(int fd, const std::string& data)
{
	return ::write(fd, data.data(), data.size()) == static_cast<ssize_t>(data.size());
}

std::string read_all(int fd)
{
	std::string out;
	char		buffer[SWDIVERT_ECHO_CAPACITY + 1];
	ssize_t		count;
	::lseek(fd, 0, SEEK_SET);
	while ((count = ::read(fd, buffer, sizeof(buffer))) > 0)
		out.append(buffer, static_cast<size_t>(count));
	return out;
}
}  // namespace

int main()
{
	const int fd = ::open("/dev/" SWDIVERT_ECHO_DEVICE_NAME, O_RDWR);
	if (fd < 0)
	{
		std::fprintf(stderr,
					 "cannot open /dev/%s: %s (is the module loaded, and are you root?)\n",
					 SWDIVERT_ECHO_DEVICE_NAME,
					 std::strerror(errno));
		return 2;
	}

	__u32 version = 0;
	check(::ioctl(fd, SWDIVERT_ECHO_IOC_VERSION, &version) == 0 && version == SWDIVERT_ECHO_ABI_VERSION,
		  "ioctl reports the expected ABI version");

	check(write_all(fd, "hello kernel") && read_all(fd) == "hello kernel", "a write is echoed back");
	check(write_all(fd, "x") && read_all(fd) == "x", "a second write replaces the first");

	const std::string binary("a\0b\xff", 4);
	check(write_all(fd, binary) && read_all(fd) == binary, "binary data round-trips");

	const int other = ::open("/dev/" SWDIVERT_ECHO_DEVICE_NAME, O_RDONLY);
	check(other >= 0 && read_all(other) == binary, "a second open sees the stored message");
	if (other >= 0)
		::close(other);

	check(write_all(fd, std::string(SWDIVERT_ECHO_CAPACITY, 'z')) && read_all(fd).size() == SWDIVERT_ECHO_CAPACITY,
		  "a full-capacity message is accepted");
	const std::string too_big(SWDIVERT_ECHO_CAPACITY + 1, 'z');
	errno = 0;
	check(::write(fd, too_big.data(), too_big.size()) < 0 && errno == EMSGSIZE, "an oversized write fails with EMSGSIZE");
	check(read_all(fd).size() == SWDIVERT_ECHO_CAPACITY, "a rejected write leaves the stored message intact");

	errno = 0;
	check(::ioctl(fd, _IO('s', 0x7f)) < 0 && errno == ENOTTY, "an unknown ioctl fails with ENOTTY");

	::close(fd);
	std::printf("%s\n", g_failures == 0 ? "all checks passed" : "checks failed");
	return g_failures == 0 ? 0 : 1;
}
