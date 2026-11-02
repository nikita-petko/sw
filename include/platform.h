#ifndef PLATFORM_H_
#define PLATFORM_H_

#include <cstdint>
#include <string>

/// Operating-system services needed by the application, with one implementation per OS
/// (src/platform/windows/ and src/platform/posix/).
namespace platform {

/// Key codes used in profile configuration and by the input functions. The values match the
/// Windows virtual-key codes so existing profiles keep working on every platform; letters and
/// digits use their upper-case ASCII value.
namespace key {
inline constexpr int none	   = -1;
inline constexpr int backspace = 0x08;
inline constexpr int tab	   = 0x09;
inline constexpr int shift	   = 0x10;
inline constexpr int ctrl	   = 0x11;
inline constexpr int alt	   = 0x12;
inline constexpr int space	   = 0x20;
inline constexpr int page_up   = 0x21;
inline constexpr int page_down = 0x22;
inline constexpr int left	   = 0x25;
inline constexpr int up		   = 0x26;
inline constexpr int right	   = 0x27;
inline constexpr int down	   = 0x28;
}  // namespace key

/// Key codes returned by read_edit_key(). Printable characters are reported as themselves; everything else is a value
/// above the byte range, so no key can be confused with a typed character.
namespace edit_key {
inline constexpr int none	   = -1;
inline constexpr int ctrl_flag = 0x10000;
inline constexpr int special   = 0x20000;
inline constexpr int escape	   = special + 1;
inline constexpr int enter	   = special + 2;
inline constexpr int tab	   = special + 3;
inline constexpr int backspace = special + 4;
inline constexpr int del	   = special + 5;
inline constexpr int home	   = special + 6;
inline constexpr int end	   = special + 7;
inline constexpr int up		   = special + 8;
inline constexpr int down	   = special + 9;
inline constexpr int left	   = special + 10;
inline constexpr int right	   = special + 11;
inline constexpr int page_up   = special + 12;
inline constexpr int page_down = special + 13;
/// The process was asked to terminate (SIGTERM/SIGHUP on POSIX).
inline constexpr int terminate = special + 14;
/// Ctrl plus a letter ('A'-'Z').
constexpr int ctrl(char letter)
{
	return ctrl_flag | letter;
}
}  // namespace edit_key

/// Monotonic milliseconds since an arbitrary point (system boot on Windows).
uint64_t tick_ms();
/// Sleeps the calling thread.
void	 sleep_ms(uint32_t milliseconds);
/// Requests ~1ms timer granularity for accurate packet release timing. Calls must be balanced.
void	 begin_timer_resolution();
/// Releases a request made by begin_timer_resolution().
void	 end_timer_resolution();

/// Generates a random GUID in its hyphenated form; returns an empty string on failure.
std::string generate_guid();

/// Prepares the console so ANSI escape sequences are interpreted.
void enable_terminal_colors();
/// Makes Ctrl+C a no-op so the tool can only be closed via its own quit key. On POSIX, SIGTERM and SIGHUP
/// request a normal quit (read_key() then returns 'q').
void ignore_interrupt();
/// Claims the machine-wide single-instance lock, held until the process exits. Returns false when another
/// instance already holds it.
bool acquire_single_instance();
/// Width of the console in columns, or 0 when unknown.
int	 console_width();
/// Height of the console in rows, or 0 when unknown.
int	 console_height();

/// Host counters sampled by the net monitor.
struct SystemCounters
{
	/// Receive/transmit errors and drops summed over all non-loopback interfaces; valid when `nic_available`.
	uint64_t nic_errors		= 0;
	uint64_t nic_drops		= 0;
	bool	 nic_available	= false;
	/// CPU time used by this process so far, in seconds; valid when `cpu_available`.
	double	 cpu_seconds	= 0;
	bool	 cpu_available	= false;
};
/// Reads the host counters; unavailable ones are flagged instead of reported as zero.
SystemCounters system_counters();

/// Per-user directory for lagsw's persistent files (not created); empty when unavailable.
std::string data_directory();
/// Per-user directory for lagsw's settings, such as the list of recently opened profile files (not created); empty
/// when unavailable.
std::string config_directory();
/// Whether both input and output are an interactive terminal.
bool		is_interactive();
/// Creates a directory (and ignores the error if it already exists).
void		make_directory(const std::string& path);
/// Atomically replaces `destination` with `source`; returns false and removes `source` on failure.
bool		replace_file(const std::string& source, const std::string& destination);

/// Returns the next pending key press (a key:: constant, or an ASCII character), or key::none.
int	 read_key();
/// Like read_key(), but for text editing: reports typed characters, Escape, Enter, Delete, Home/End and Ctrl+letter
/// as edit_key codes, or edit_key::none when nothing is pending.
int	 read_edit_key();
/// Returns whether the key is currently held down, system wide.
bool is_key_held(int key);

/// HTTP status, retry delay, and response body returned by an HTTPS request.
struct HttpResponse
{
	/// HTTP response status code (0 when the request failed).
	uint32_t	status				= 0;
	/// Server-provided delay before retrying a rate-limited request.
	uint32_t	retry_after_seconds = 0;
	/// Response body.
	std::string body;
};

/// Performs an HTTPS GET with short timeouts. `host` is a bare host name and `path` starts with '/'.
HttpResponse https_get(const std::string& host, const std::string& path);

}  // namespace platform

#endif
