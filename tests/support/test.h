// Minimal test harness shared by the unit-test targets. Each test file defines its cases as plain functions, lists them in a
// TestCase array and returns run_tests() from main().
#ifndef TESTS_SUPPORT_TEST_H_
#define TESTS_SUPPORT_TEST_H_

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace test {

inline int& failure_count()
{
	static int failures = 0;
	return failures;
}

struct TestCase
{
	const char* name;
	void (*run)();
};

namespace detail {
struct Running
{
	std::atomic<const char*> suite{nullptr};
	std::atomic<const char*> name{nullptr};
	std::atomic<long long>	 started_ms{0};
};

inline Running& running()
{
	static Running state;
	return state;
}

inline long long now_ms()
{
	return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

/// Ends the process when one test runs longer than LAGSW_TEST_TIMEOUT_S seconds (default 120), naming the test. A deadlocked
/// worker thread would otherwise hang the whole run silently, and a killed process loses its buffered output.
inline void start_watchdog()
{
	static const bool started = [] {
		const char*		  text	   = std::getenv("LAGSW_TEST_TIMEOUT_S");
		const long long	  seconds  = text != nullptr && std::atoll(text) > 0 ? std::atoll(text) : 120;
		const long long	  limit_ms = seconds * 1000;
		std::thread([limit_ms] {
			for (;;)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(200));
				const char* name = running().name.load();
				if (name != nullptr && now_ms() - running().started_ms.load() > limit_ms)
				{
					std::fprintf(stderr, "%s::%s: TIMEOUT after %lld s, giving up\n", running().suite.load(), name, limit_ms / 1000);
					std::fflush(stderr);
					std::_Exit(124);
				}
			}
		}).detach();
		return true;
	}();
	(void)started;
}
}  // namespace detail

/// Runs the cases whose name contains argv[1] (all of them without an argument) and returns the process exit code.
template <size_t N>
int run_tests(const char* suite, const TestCase (&cases)[N], int argc, char** argv)
{
	detail::start_watchdog();
	const char* filter = argc > 1 ? argv[1] : nullptr;
	int			ran	   = 0;
	for (const TestCase& test_case : cases)
	{
		if (filter != nullptr && std::strstr(test_case.name, filter) == nullptr)
			continue;
		const int before = failure_count();
		detail::running().suite		= suite;
		detail::running().started_ms = detail::now_ms();
		detail::running().name		= test_case.name;
		test_case.run();
		detail::running().name = nullptr;
		std::printf("[%s] %s::%s\n", failure_count() == before ? " ok " : "FAIL", suite, test_case.name);
		std::fflush(stdout);
		++ran;
	}
	if (ran == 0)
	{
		std::fprintf(stderr, "%s: no test matches '%s'\n", suite, filter != nullptr ? filter : "");
		return 1;
	}
	std::printf("%s: %d test(s) run, %d check(s) failed\n", suite, ran, failure_count());
	return failure_count() == 0 ? 0 : 1;
}

}  // namespace test

#define CHECK(condition)                                                                       \
	do                                                                                         \
	{                                                                                          \
		if (!(condition))                                                                      \
		{                                                                                      \
			std::fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition); \
			++test::failure_count();                                                           \
		}                                                                                      \
	} while (false)

#endif
