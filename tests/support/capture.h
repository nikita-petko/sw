// Captures what code under test writes to stdout (the logger writes there).
#ifndef TESTS_SUPPORT_CAPTURE_H_
#define TESTS_SUPPORT_CAPTURE_H_

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <string>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace test {
namespace detail {
inline int duplicate(int descriptor)
{
#ifdef _WIN32
	return _dup(descriptor);
#else
	return dup(descriptor);
#endif
}

inline void redirect(int from, int to)
{
#ifdef _WIN32
	_dup2(from, to);
	_close(from);
#else
	dup2(from, to);
	close(from);
#endif
}

inline int descriptor_of(std::FILE* file)
{
#ifdef _WIN32
	return _fileno(file);
#else
	return fileno(file);
#endif
}
}  // namespace detail

/// Runs `body` and returns everything it wrote to stdout.
inline std::string capture_stdout(const std::function<void()>& body)
{
	const std::filesystem::path path = std::filesystem::temp_directory_path() / "lagsw_test_stdout.txt";
	std::fflush(stdout);
	const int  saved  = detail::duplicate(detail::descriptor_of(stdout));
	std::FILE* target = std::fopen(path.string().c_str(), "wb");
	detail::redirect(detail::duplicate(detail::descriptor_of(target)), detail::descriptor_of(stdout));
	body();
	std::fflush(stdout);
	detail::redirect(saved, detail::descriptor_of(stdout));
	std::fclose(target);
	std::string text;
	{
		std::ifstream file(path, std::ios::binary);
		text.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
	}
	std::filesystem::remove(path);
	return text;
}

}  // namespace test

#endif
