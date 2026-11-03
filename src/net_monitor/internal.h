#ifndef NET_MONITOR_INTERNAL_H_
#define NET_MONITOR_INTERNAL_H_

// Shared by the net monitor sources: tuning constants, terminal colors and the free helper functions (helpers.cc, text.cc).

#include <chrono>
#include <cstdint>
#include <deque>
#include <string>
#include <vector>

#include "packet_headers.h"

namespace net_monitor_detail {
using Clock = std::chrono::steady_clock;

inline constexpr size_t   kHistory			  = 600;  // seconds of history kept; wide terminals show as much as fits
inline constexpr size_t   kRttWindow		  = 256;  // RTT samples used for the percentiles
inline constexpr size_t   kPendingPerFlow	  = 128;
inline constexpr size_t   kMaxFlowsPerServer = 256;
inline constexpr size_t   kMaxPorts		  = 64;
inline constexpr double   kStallMs			  = 250;  // an inbound gap at least this long counts as a stall
inline constexpr size_t   kMaxEvents		  = 200;
inline constexpr size_t   kRetransmitWindow  = 10;	 // seconds of history behind the retransmit alert
inline constexpr uint64_t kMinAlertData	  = 20;	 // data packets needed in that window before a retransmit percentage means anything
inline constexpr size_t   kEventRows		  = 4;
inline constexpr auto	   kStatusLifetime	  = std::chrono::seconds(8);
inline constexpr auto	   kCaptureRetry	  = std::chrono::seconds(5);
inline constexpr auto	   kTickInterval	  = std::chrono::seconds(1);
inline constexpr auto	   kFrameInterval	  = std::chrono::milliseconds(200);

inline const char* const kReset  = "\033[0m";
inline const char* const kDim	  = "\033[90m";
inline const char* const kBold	  = "\033[1m";
inline const char* const kGreen  = "\033[32m";
inline const char* const kYellow = "\033[33m";
inline const char* const kRed	  = "\033[31m";
inline const char* const kCyan	  = "\033[36m";

inline constexpr uint32_t kSizeLimits[] = {128, 512, 1024};
inline const char* const  kSizeLabels[] = {"<128 B", "128-511 B", "512-1023 B", ">=1024 B"};

inline constexpr double  kRttLimits[] = {25, 50, 100, 200, 500};
inline const char* const kRttLabels[] = {"<25 ms", "25-49 ms", "50-99 ms", "100-199 ms", "200-499 ms", ">=500 ms"};

// Packet and statistics helpers (helpers.cc).

/// Sequence-number comparison that survives wraparound.
bool seq_gt(uint32_t a, uint32_t b);

double elapsed_ms(Clock::time_point from, Clock::time_point to);

/// Bytes of transport payload in an IP packet, or 0 when it cannot be determined.
uint32_t payload_length(const ParsedPacket& parsed, uint32_t captured_length);

const char* service_name(uint16_t port);

size_t rtt_bucket(double rtt_ms);

size_t size_bucket(uint32_t length);

double percentile(std::vector<double> samples, double fraction);

double last_value(const std::deque<double>& values);

/// The initial TTL a sender most likely used (the next common default at or above the observed value).
int initial_ttl(int observed);

/// Link quality from 0 to 100, based on everything measured since the view was opened. -1 when nothing was seen.
double stability_score(double retransmit_percent, double jitter_ms, double arrival_jitter_ms, uint64_t resets, uint64_t stalls);

// Terminal rendering helpers (text.cc).

const char* rtt_color(double rtt_ms);

const char* loss_color(double percent);

const char* score_color(double score);

std::string format_size(double bytes);

std::string format_rate(double bytes_per_second);

std::string bar(double fraction, size_t width);

/// Whole-second spans, scaled from seconds up to days.
std::string format_age(double seconds);

/// A duration given in milliseconds, scaled to ms, s, minutes, hours or days.
std::string format_ms(double value, bool available = true);

/// A signed millisecond difference, scaled like format_ms().
std::string format_ms_delta(double value);

std::string format_clock(uint64_t seconds);

std::string pad(const std::string& text, size_t width);

std::string pad_left(const std::string& text, size_t width);

/// Renders the last `width` values as a block-character chart. The scale starts at zero and ends at the
/// window maximum (at least `floor`, so an idle line does not look busy).
std::string sparkline(const std::deque<double>& values, size_t width, double floor, const char* color);

/// A multi-row variant of sparkline(): the value range is split over `rows` * 8 levels, top row first.
std::vector<std::string> chart_rows(const std::deque<double>& values, size_t width, double floor, const char* color, size_t rows);

/// Like chart_rows(), but also shows the per-second spread: a darker bar up to the lowest value, the mean above it and a
/// thin line up to the highest value. A single row cannot show the spread and falls back to the plain chart.
std::vector<std::string> band_rows(const std::deque<double>& mean,
								   const std::deque<double>& low,
								   const std::deque<double>& high,
								   size_t					 width,
								   double					 floor,
								   const char*				 color,
								   size_t					 rows);

/// One row that marks the seconds in which `values` is above zero.
std::string marker_row(const std::deque<double>& values, size_t width, const char* color);

}  // namespace net_monitor_detail

#endif
