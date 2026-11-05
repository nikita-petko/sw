#ifndef KMOD_MODULE_IMAGE_H_
#define KMOD_MODULE_IMAGE_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace kmodb {

/// A kernel module as bytes: what is embedded in the executable, or read from a file.
struct ModuleImage
{
	const uint8_t* data = nullptr;
	size_t		   size = 0;
};

/// The `vermagic` string of a module ("7.2.11-arch1-1 SMP preempt mod_unload "), read from its .modinfo strings; empty when `data` is not
/// a module. The kernel refuses a module whose vermagic differs from its own, which is why a module is built for one kernel: the first
/// word is the kernel release.
inline std::string image_vermagic(const uint8_t* data, size_t size)
{
	static const char kKey[]	 = "vermagic=";
	constexpr size_t  kKeyLength = sizeof(kKey) - 1;
	if (data == nullptr || size < 64 ||
		std::memcmp(data,
					"\x7f"
					"ELF",
					4) != 0)
		return {};
	// .modinfo is a run of NUL-terminated "key=value" strings
	for (size_t at = 1; at + kKeyLength < size; ++at)
	{
		if (data[at - 1] != 0 || data[at] != 'v' || std::memcmp(data + at, kKey, kKeyLength) != 0)
			continue;
		size_t end = at + kKeyLength;
		while (end < size && data[end] != 0)
			++end;
		return std::string(reinterpret_cast<const char*>(data + at + kKeyLength), end - at - kKeyLength);
	}
	return {};
}

/// The kernel release a module was built for (the first word of its vermagic), or an empty string.
inline std::string image_release(const uint8_t* data, size_t size)
{
	const std::string vermagic = image_vermagic(data, size);
	return vermagic.substr(0, vermagic.find(' '));
}

/// The image built for `release` (the running kernel's `uname -r`), or null; `why_not` then says which releases there are. Images that
/// are not modules are ignored.
inline const ModuleImage* select_image(const std::vector<ModuleImage>& images, const std::string& release, std::string& why_not)
{
	std::string available;
	for (const ModuleImage& image : images)
	{
		const std::string built_for = image_release(image.data, image.size);
		if (built_for.empty())
			continue;
		if (built_for == release)
			return &image;
		available += (available.empty() ? "" : ", ") + built_for;
	}
	why_not = available.empty() ? "no module is embedded in this build"
								: "the embedded modules are for kernel " + available + ", this kernel is " + release;
	return nullptr;
}

}  // namespace kmodb

#endif
