#ifndef KMOD_FILTER_PROGRAM_H_
#define KMOD_FILTER_PROGRAM_H_

#include <cstdint>
#include <string>
#include <vector>

#include "swdivert_abi.h"
#include "swdivert_vm.h"

/// Compiles a WinDivert-style filter string into a program for the swdivert filter VM (kmod/include/swdivert_abi.h).
///
/// The lexer, parser and DNF conversion are the ones of the NFQUEUE backend (backends/nfqueue/filter_*.cc), so both backends accept exactly
/// the same filters and read them the same way; this file only turns each DNF clause (a `nfq::CompiledRule` of typed matches) into a run of
/// tests that ends in ACCEPT. A test that fails jumps to the next clause. Address lists become sorted sets (one search, not one test per
/// address); identical sets of different clauses are shared.
namespace kmodf {

struct SetData
{
	uint32_t			  kind = SWDIV_SET_IPV4;
	std::vector<uint32_t> elems;
};

struct Program
{
	std::vector<swdiv_insn> insns;
	std::vector<SetData>	sets;
	/// The hooks the filter can match at, as SWDIV_OPEN_LOCAL_IN | SWDIV_OPEN_LOCAL_OUT | SWDIV_OPEN_FORWARD; a handle is opened for
	/// exactly these. 0 when the filter matches nothing (open the handle for any layer: its program has no instructions).
	uint32_t layers = 0;
};

/// Compiles `filter`. `forward` and `include_forward` choose the layers as in backend::OpenOptions: local traffic (input and output), only
/// forwarded traffic, or both. When the clauses span more than one hook each starts with a test of SWDIV_SRC_HOOK. On failure `error` and
/// `position` (byte offset into `filter`) describe the problem. An empty filter matches every IPv4 packet; `false` yields a program
/// without instructions.
bool compile_program(const std::string& filter,
					 Program&			out,
					 std::string&		error,
					 uint32_t&			position,
					 bool				forward			= true,
					 bool				include_forward = false);

/// Applies the kernel's checks (swdiv_vm_verify_set and swdiv_vm_verify); returns an empty string when the program would be accepted.
std::string verify_program(const Program& program);

/// The sets of a program as the interpreter takes them (the views point into `program`).
std::vector<swdiv_vm_set> vm_sets(const Program& program);

/// Installs `program` on an open /dev/swdivert handle (SWDIVERT_IOC_SET_PROGRAM). Returns the ioctl's result; errno is set on failure.
int install_program(int fd, const Program& program);

}  // namespace kmodf

#endif
