// Minimal test harness shared by the unit-test targets. Each test file defines its cases as plain functions, lists them in a
// TestCase array and returns run_tests() from main().
#ifndef TESTS_SUPPORT_TEST_H_
#define TESTS_SUPPORT_TEST_H_

#include <cstddef>
#include <cstdio>
#include <cstring>

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

/// Runs the cases whose name contains argv[1] (all of them without an argument) and returns the process exit code.
template <size_t N>
int run_tests(const char* suite, const TestCase (&cases)[N], int argc, char** argv)
{
	const char* filter = argc > 1 ? argv[1] : nullptr;
	int			ran	   = 0;
	for (const TestCase& test_case : cases)
	{
		if (filter != nullptr && std::strstr(test_case.name, filter) == nullptr)
			continue;
		const int before = failure_count();
		test_case.run();
		std::printf("[%s] %s::%s\n", failure_count() == before ? " ok " : "FAIL", suite, test_case.name);
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
