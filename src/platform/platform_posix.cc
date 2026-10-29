#ifdef _WIN32
#error "platform_posix.cc must not be built on Windows"
#endif

#include "platform.h"

#include <curl/curl.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#include <array>
#include <chrono>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace platform {
namespace {
// restores the terminal settings changed by read_key()
termios original_terminal;
bool	terminal_raw = false;

void restore_terminal()
{
	if (terminal_raw)
		tcsetattr(STDIN_FILENO, TCSANOW, &original_terminal);
}

void enter_raw_terminal()
{
	if (terminal_raw || !isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &original_terminal) != 0)
		return;
	termios raw = original_terminal;
	// keeps ISIG so Ctrl+C still stops the application
	raw.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO));
	raw.c_cc[VMIN]	= 0;
	raw.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0)
		return;
	terminal_raw = true;
	std::atexit(restore_terminal);
}

int read_byte()
{
	unsigned char value = 0;
	return read(STDIN_FILENO, &value, 1) == 1 ? value : -1;
}

/// Maps a platform::key code to a Linux input event code, or -1 when unsupported.
int to_input_code(int code)
{
	static const int letters[26] = {KEY_A, KEY_B, KEY_C, KEY_D, KEY_E, KEY_F, KEY_G, KEY_H, KEY_I, KEY_J, KEY_K, KEY_L, KEY_M,
									KEY_N, KEY_O, KEY_P, KEY_Q, KEY_R, KEY_S, KEY_T, KEY_U, KEY_V, KEY_W, KEY_X, KEY_Y, KEY_Z};
	static const int digits[10]	 = {KEY_0, KEY_1, KEY_2, KEY_3, KEY_4, KEY_5, KEY_6, KEY_7, KEY_8, KEY_9};
	static const int function_keys[12] = {KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5, KEY_F6, KEY_F7, KEY_F8, KEY_F9, KEY_F10, KEY_F11, KEY_F12};
	if (code >= 'A' && code <= 'Z')
		return letters[code - 'A'];
	if (code >= '0' && code <= '9')
		return digits[code - '0'];
	if (code >= 0x70 && code <= 0x7B)
		return function_keys[code - 0x70];
	switch (code)
	{
		case key::backspace:
			return KEY_BACKSPACE;
		case key::tab:
			return KEY_TAB;
		case key::space:
			return KEY_SPACE;
		case key::page_up:
			return KEY_PAGEUP;
		case key::page_down:
			return KEY_PAGEDOWN;
		case key::left:
			return KEY_LEFT;
		case key::right:
			return KEY_RIGHT;
	}
	return -1;
}

/// Test hook: when LAGSW_TEST_KEYS names a file, the whitespace-separated key names in it (a, x, 1, space, shift, ctrl, alt)
/// are reported as held instead of reading the keyboards. This lets automated tests drive activation without input devices.
bool test_key_held(const char* path, int code)
{
	std::ifstream file(path);
	std::string	  name;
	while (file >> name)
	{
		int held = -1;
		if (name == "space")
			held = key::space;
		else if (name == "shift")
			held = key::shift;
		else if (name == "ctrl")
			held = key::ctrl;
		else if (name == "alt")
			held = key::alt;
		else if (name == "tab")
			held = key::tab;
		else if (name.size() == 1)
			held = std::toupper(static_cast<unsigned char>(name[0]));
		if (held == code)
			return true;
	}
	return false;
}

/// Reads key state straight from the evdev keyboards, so keys are seen regardless of terminal focus.
class KeyboardState
{
public:
	~KeyboardState()
	{
		for (const int descriptor : descriptors_)
			close(descriptor);
	}

	bool held(int code)
	{
		if (const char* test_keys = std::getenv("LAGSW_TEST_KEYS"))
			return test_key_held(test_keys, code);
		std::lock_guard<std::mutex> lock(mutex_);
		refresh();
		bool result = false;
		switch (code)
		{
			case key::shift:
				result = any(KEY_LEFTSHIFT) || any(KEY_RIGHTSHIFT);
				break;
			case key::ctrl:
				result = any(KEY_LEFTCTRL) || any(KEY_RIGHTCTRL);
				break;
			case key::alt:
				result = any(KEY_LEFTALT) || any(KEY_RIGHTALT);
				break;
			default:
				const int input_code = to_input_code(code);
				result				 = input_code >= 0 && any(input_code);
		}
		return result;
	}

private:
	static constexpr size_t kBitmapBytes = KEY_MAX / 8 + 1;
	using Bitmap						 = unsigned char[kBitmapBytes];

	void open_devices()
	{
		DIR* directory = opendir("/dev/input");
		if (!directory)
			return;
		while (const dirent* entry = readdir(directory))
		{
			if (std::strncmp(entry->d_name, "event", 5) != 0)
				continue;
			const std::string path = std::string("/dev/input/") + entry->d_name;
			const int		  descriptor = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
			if (descriptor < 0)
				continue;
			Bitmap bits = {};
			// only devices that report key events can be keyboards
			if (ioctl(descriptor, EVIOCGBIT(EV_KEY, sizeof(bits)), bits) < 0 || !test(bits, KEY_A))
			{
				close(descriptor);
				continue;
			}
			descriptors_.push_back(descriptor);
		}
		closedir(directory);
	}

	static bool test(const unsigned char* bits, int code)
	{
		return (bits[code / 8] >> (code % 8)) & 1;
	}

	void refresh()
	{
		const auto now = std::chrono::steady_clock::now();
		if (descriptors_.empty() && now - last_scan_ > std::chrono::seconds(5))
		{
			last_scan_ = now;
			open_devices();
		}
		// callers poll several keys per tick, so one snapshot is shared for a few milliseconds
		if (now - last_snapshot_ < std::chrono::milliseconds(3))
			return;
		last_snapshot_ = now;
		snapshots_.assign(descriptors_.size(), {});
		for (size_t index = 0; index < descriptors_.size(); ++index)
			if (ioctl(descriptors_[index], EVIOCGKEY(sizeof(Bitmap)), snapshots_[index].data()) < 0)
				snapshots_[index].fill(0);
	}

	bool any(int input_code) const
	{
		for (const auto& snapshot : snapshots_)
			if (test(snapshot.data(), input_code))
				return true;
		return false;
	}

	std::mutex											  mutex_;
	std::vector<int>									  descriptors_;
	std::vector<std::array<unsigned char, kBitmapBytes>> snapshots_;
	std::chrono::steady_clock::time_point				  last_scan_	 = {};
	std::chrono::steady_clock::time_point				  last_snapshot_ = {};
};

size_t write_body(char* data, size_t size, size_t count, void* user)
{
	static_cast<std::string*>(user)->append(data, size * count);
	return size * count;
}

size_t read_header(char* data, size_t size, size_t count, void* user)
{
	const size_t	   length = size * count;
	const std::string  line(data, length);
	static const char  name[] = "retry-after:";
	if (line.size() > sizeof(name) - 1 && strncasecmp(line.c_str(), name, sizeof(name) - 1) == 0)
	{
		char*			   end	 = nullptr;
		const unsigned long value = std::strtoul(line.c_str() + sizeof(name) - 1, &end, 10);
		if (end != line.c_str() + sizeof(name) - 1)
			static_cast<HttpResponse*>(user)->retry_after_seconds = static_cast<uint32_t>(value);
	}
	return length;
}
}  // namespace

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

std::atomic<bool> g_terminate_requested{false};

extern "C" void on_terminate_signal(int)
{
	g_terminate_requested.store(true);
}

// SIGTERM/SIGHUP are treated like the quit key so the capture backend can remove its rules on a normal exit.
void ignore_interrupt()
{
	std::signal(SIGINT, SIG_IGN);
	std::signal(SIGTERM, on_terminate_signal);
	std::signal(SIGHUP, on_terminate_signal);
}

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

int read_key()
{
	if (g_terminate_requested.load())
		return 'q';
	enter_raw_terminal();
	const int value = read_byte();
	if (value < 0)
		return key::none;
	if (value == 127)
		return key::backspace;
	if (value != 0x1B)
		return value;
	if (read_byte() != '[')
		return key::none;
	switch (read_byte())
	{
		case 'D':
			return key::left;
		case 'C':
			return key::right;
		case '5':
			read_byte();  // trailing '~'
			return key::page_up;
		case '6':
			read_byte();  // trailing '~'
			return key::page_down;
	}
	return key::none;
}

bool is_key_held(int code)
{
	static KeyboardState keyboard;
	return keyboard.held(code);
}

HttpResponse https_get(const std::string& host, const std::string& path)
{
	HttpResponse result;
	CURL*		 curl = curl_easy_init();
	if (!curl)
		return result;
	const std::string url = "https://" + host + path;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_USERAGENT, "lagsw/1.0");
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 9000L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 3000L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, read_header);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &result);
	if (curl_easy_perform(curl) == CURLE_OK)
	{
		long status = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
		result.status = static_cast<uint32_t>(status);
	}
	curl_easy_cleanup(curl);
	return result;
}

}  // namespace platform
