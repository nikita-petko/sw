// eBPF egress shaping (see shaper.h). Everything that touches the kernel lives here: loading the embedded program, attaching it to
// the configured interfaces with tcx, installing `fq` on them and restoring the previous root qdisc on an orderly exit.
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "filter_compiler.h"
#include "lagsw_bpf_obj.h"
#include "log.h"
#include "shaper.h"
#include "shaper/bpf_shared.h"
#include "shaper/qdisc.h"
#include "shaper_plan.h"

LOG_DEFAULT_GROUP(logging::group::nfq)

namespace nfq::shaper {
namespace {
constexpr int kDrainTimeoutMs = 2000;

std::mutex	libbpf_log_mutex;
std::string libbpf_last_message;

int libbpf_print(enum libbpf_print_level level, const char* format, va_list arguments)
{
	char buffer[1024];
	std::vsnprintf(buffer, sizeof(buffer), format, arguments);
	std::string text(buffer);
	while (!text.empty() && (text.back() == '\n' || text.back() == ' '))
		text.pop_back();
	if (text.empty())
		return 0;
	if (level <= LIBBPF_WARN)
	{
		std::lock_guard<std::mutex> lock(libbpf_log_mutex);
		libbpf_last_message = text;
	}
	LOG_DEBUG("libbpf: %s", text.c_str());
	return 0;
}

std::string last_libbpf_message()
{
	std::lock_guard<std::mutex> lock(libbpf_log_mutex);
	return libbpf_last_message;
}

std::string errno_text(int code)
{
	return std::strerror(code < 0 ? -code : code);
}

struct Interface
{
	std::string		   name;
	qdisc::Interface   info;
	std::string		   previous_kind;
	bool			   fq_installed = false;
	bpf_link*		   link			= nullptr;
};

class BpfStage;

class Shaper
{
public:
	static Shaper& instance()
	{
		static Shaper shaper;
		return shaper;
	}

	void configure(const backend::ShapingConfig& config)
	{
		std::lock_guard<std::mutex> lock(mutex_);
		config_ = config;
	}

	std::unique_ptr<backend::ShapeStage> open(const backend::ShapeSpec& spec, std::string& reason);
	std::string							 status();
	void								 shutdown();

	// Stage operations; stages call these and never touch the maps directly.
	bool write_stage(uint32_t slot, const lagsw_stage& stage, std::string& error);
	bool reset_state(uint32_t slot);
	backend::ShapeStats read_stats(uint32_t slot);
	void release(uint32_t slot, const std::vector<shaping::AddressSet>& sets);

private:
	Shaper() = default;
	~Shaper() { shutdown(); }

	bool initialize(std::string& reason);
	void rollback();
	bool fill_normal_scores();
	bool add_sets(const std::vector<shaping::AddressSet>& sets, std::string& error);
	void remove_sets(const std::vector<shaping::AddressSet>& sets);

	std::mutex				 mutex_;
	backend::ShapingConfig	 config_;
	bool					 tried_	 = false;
	bool					 ready_	 = false;
	std::string				 failure_;
	bpf_object*				 object_ = nullptr;
	int						 stages_fd_ = -1, state_fd_ = -1, stats_fd_ = -1, addrs_fd_ = -1, ifinfo_fd_ = -1, normal_fd_ = -1;
	std::vector<Interface>	 interfaces_;
	bool					 used_[LAGSW_MAX_STAGES] = {};
	int						 cpu_count_ = 1;
};

class BpfStage final : public backend::ShapeStage
{
public:
	BpfStage(Shaper& shaper, uint32_t slot, const lagsw_stage& stage, std::vector<shaping::AddressSet> sets, std::string label)
		: shaper_(shaper), slot_(slot), stage_(stage), sets_(std::move(sets)), label_(std::move(label))
	{
	}

	~BpfStage() override
	{
		deactivate();
		shaper_.release(slot_, sets_);
	}

	bool activate(std::string& error) override
	{
		if (active_)
			return true;
		shaper_.reset_state(slot_);
		baseline_		= shaper_.read_stats(slot_);
		stage_.active	= 1;
		if (!shaper_.write_stage(slot_, stage_, error))
		{
			stage_.active = 0;
			return false;
		}
		active_ = true;
		LOG_DEBUG("eBPF stage %u (%s) activated", slot_, label_.c_str());
		return true;
	}

	void deactivate() override
	{
		if (!active_)
			return;
		stage_.active = 0;
		std::string error;
		if (!shaper_.write_stage(slot_, stage_, error))
			LOG_WARN("eBPF stage %u (%s): failed to deactivate: %s", slot_, label_.c_str(), error.c_str());
		active_ = false;
		[[maybe_unused]] const backend::ShapeStats now = shaper_.read_stats(slot_);
		LOG_DEBUG("eBPF stage %u (%s) deactivated: %llu matched, %llu delayed, %llu dropped", slot_, label_.c_str(),
				  static_cast<unsigned long long>(now.matched - baseline_.matched), static_cast<unsigned long long>(now.delayed - baseline_.delayed),
				  static_cast<unsigned long long>(now.dropped - baseline_.dropped));
	}

	backend::ShapeStats stats() const override
	{
		backend::ShapeStats now = shaper_.read_stats(slot_);
		now.matched -= baseline_.matched;
		now.delayed -= baseline_.delayed;
		now.dropped -= baseline_.dropped;
		now.clamped -= baseline_.clamped;
		return now;
	}

private:
	Shaper&							   shaper_;
	const uint32_t					   slot_;
	lagsw_stage						   stage_;
	std::vector<shaping::AddressSet> sets_;
	std::string						   label_;
	backend::ShapeStats				   baseline_;
	bool							   active_ = false;
};

shaping::Behaviour to_behaviour(backend::ShapeBehaviour behaviour)
{
	switch (behaviour)
	{
		case backend::ShapeBehaviour::fixed_delay:
			return shaping::Behaviour::fixed_delay;
		case backend::ShapeBehaviour::drop:
			return shaping::Behaviour::drop;
		case backend::ShapeBehaviour::batch_delay:
			return shaping::Behaviour::batch_delay;
		case backend::ShapeBehaviour::baseline:
			return shaping::Behaviour::baseline;
	}
	return shaping::Behaviour::fixed_delay;
}

shaping::Model to_model(backend::ShapeModel model)
{
	switch (model)
	{
		case backend::ShapeModel::fixed:
			return shaping::Model::fixed;
		case backend::ShapeModel::uniform:
			return shaping::Model::uniform;
		case backend::ShapeModel::normal:
			return shaping::Model::normal;
	}
	return shaping::Model::fixed;
}

std::unique_ptr<backend::ShapeStage> Shaper::open(const backend::ShapeSpec& spec, std::string& reason)
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (config_.tier == backend::ShapingTier::capture)
	{
		reason = "kernel shaping is disabled by the configuration";
		return nullptr;
	}
	if (config_.interfaces.empty())
	{
		reason = "no interfaces are configured for kernel shaping (features: linux_bpf: interfaces)";
		return nullptr;
	}

	// Decide on the stage before touching the kernel, so a profile that cannot use the tier does not install anything.
	std::vector<CompiledRule> rules;
	std::string				  error;
	uint32_t				  position = 0;
	if (!compile_filter(spec.filter, spec.forward, rules, error, position, spec.include_forward))
	{
		reason = "the filter could not be compiled: " + error;
		return nullptr;
	}
	shaping::StageSpec stage_spec;
	stage_spec.rules		  = std::move(rules);
	stage_spec.behaviour	  = to_behaviour(spec.behaviour);
	stage_spec.model		  = to_model(spec.model);
	stage_spec.delay_ms		  = spec.delay_ms;
	stage_spec.jitter_ms	  = spec.jitter_ms;
	stage_spec.max_delay_ms	  = spec.max_delay_ms;
	stage_spec.preserve_order = spec.preserve_order;
	stage_spec.ignore_inbound = spec.ignore_inbound;

	uint32_t slot = 0;
	while (slot < LAGSW_MAX_STAGES && used_[slot])
		++slot;
	if (slot == LAGSW_MAX_STAGES)
	{
		reason = "all " + std::to_string(LAGSW_MAX_STAGES) + " kernel shaping stages are in use";
		return nullptr;
	}
	shaping::Plan plan = shaping::plan_stage(stage_spec, slot * shaping::kMaxSetsPerStage);
	if (!plan.ok)
	{
		reason = plan.reason;
		return nullptr;
	}
	if (!initialize(reason))
		return nullptr;
	if (!add_sets(plan.sets, reason))
		return nullptr;
	if (!write_stage(slot, plan.stage, reason))
	{
		remove_sets(plan.sets);
		return nullptr;
	}
	used_[slot] = true;
	LOG_DEBUG("eBPF stage %u opened for %s (%zu rule(s), %zu address set(s))", slot, spec.label.c_str(), static_cast<size_t>(plan.stage.rule_count), plan.sets.size());
	return std::make_unique<BpfStage>(*this, slot, plan.stage, std::move(plan.sets), spec.label);
}

bool Shaper::initialize(std::string& reason)
{
	if (tried_)
	{
		reason = failure_;
		return ready_;
	}
	tried_ = true;
	[[maybe_unused]] const auto started = std::chrono::steady_clock::now();
	libbpf_set_print(libbpf_print);
	cpu_count_ = std::max(1, libbpf_num_possible_cpus());

	std::vector<std::string> names = config_.interfaces;
	std::sort(names.begin(), names.end());
	names.erase(std::unique(names.begin(), names.end()), names.end());
	for (const std::string& name : names)
	{
		Interface iface;
		iface.name = name;
		if (!qdisc::resolve_interface(name, iface.info, failure_))
		{
			reason = failure_;
			return false;
		}
		if (!qdisc::root_kind(iface.info.index, iface.previous_kind, failure_))
		{
			failure_ = "cannot read the root qdisc of " + name + ": " + failure_;
			reason	 = failure_;
			return false;
		}
		if (!qdisc::replaceable_kind(iface.previous_kind))
		{
			failure_ = "interface " + name + " uses the root qdisc '" + iface.previous_kind + "', which lagsw will not replace";
			reason	 = failure_;
			return false;
		}
		interfaces_.push_back(std::move(iface));
	}

	libbpf_last_message.clear();
	object_ = bpf_object__open_mem(kLagswBpfObject, kLagswBpfObjectSize, nullptr);
	if (!object_ || libbpf_get_error(object_) != 0)
	{
		failure_ = "cannot open the embedded eBPF program: " + last_libbpf_message();
		object_	 = nullptr;
		reason	 = failure_;
		return false;
	}
	const int load_error = bpf_object__load(object_);
	if (load_error != 0)
	{
		failure_ = "cannot load the eBPF program (" + errno_text(load_error) + (load_error == -EPERM ? "; CAP_BPF and CAP_PERFMON, or root, are required" : "") + "): " +
				   last_libbpf_message();
		rollback();
		reason = failure_;
		return false;
	}
	const auto fd_of = [this](const char* name) {
		bpf_map* map = bpf_object__find_map_by_name(object_, name);
		return map ? bpf_map__fd(map) : -1;
	};
	stages_fd_ = fd_of("stages");
	state_fd_  = fd_of("state");
	stats_fd_  = fd_of("stats");
	addrs_fd_  = fd_of("addrs");
	ifinfo_fd_ = fd_of("ifinfo");
	normal_fd_ = fd_of("normal_z");
	bpf_program* program = bpf_object__find_program_by_name(object_, "lagsw_egress");
	if (!program || stages_fd_ < 0 || state_fd_ < 0 || stats_fd_ < 0 || addrs_fd_ < 0 || ifinfo_fd_ < 0 || normal_fd_ < 0)
	{
		failure_ = "the embedded eBPF program is missing expected maps or programs";
		rollback();
		reason = failure_;
		return false;
	}
	if (!fill_normal_scores())
	{
		failure_ = "cannot fill the eBPF lookup table";
		rollback();
		reason = failure_;
		return false;
	}

	for (Interface& iface : interfaces_)
	{
		lagsw_ifinfo info{iface.info.l2_len};
		if (bpf_map_update_elem(ifinfo_fd_, &iface.info.index, &info, BPF_ANY) != 0)
		{
			failure_ = "cannot register interface " + iface.name + ": " + errno_text(errno);
			rollback();
			reason = failure_;
			return false;
		}
		// fq goes in first so that a packet stamped by the program is never sent immediately because of a missing qdisc.
		qdisc::FqParameters parameters;
		if (!qdisc::install_fq(iface.info.index, parameters, failure_))
		{
			failure_ = "cannot install the fq qdisc on " + iface.name + ": " + failure_ + " (CAP_NET_ADMIN is required)";
			rollback();
			reason = failure_;
			return false;
		}
		iface.fq_installed = true;
		iface.link		   = bpf_program__attach_tcx(program, static_cast<int>(iface.info.index), nullptr);
		if (!iface.link || libbpf_get_error(iface.link) != 0)
		{
			const long code = libbpf_get_error(iface.link);
			iface.link		= nullptr;
			failure_		= "cannot attach the eBPF program to " + iface.name + " (" + errno_text(static_cast<int>(code)) + "); tcx needs Linux 6.6 or newer";
			rollback();
			reason = failure_;
			return false;
		}
		LOG_INFO("Kernel shaping: eBPF egress program attached to %s (root qdisc %s replaced by fq)", iface.name.c_str(), iface.previous_kind.c_str());
	}
	ready_ = true;
	LOG_DEBUG("kernel shaping initialised in %lld ms", static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count()));
	return true;
}

void Shaper::rollback()
{
	for (Interface& iface : interfaces_)
	{
		if (iface.link)
			bpf_link__destroy(iface.link);
		iface.link = nullptr;
		if (iface.fq_installed)
		{
			std::string error;
			if (!qdisc::restore(iface.info.index, iface.previous_kind, error))
				LOG_WARN("failed to restore the %s qdisc on %s: %s", iface.previous_kind.c_str(), iface.name.c_str(), error.c_str());
			iface.fq_installed = false;
		}
	}
	interfaces_.clear();
	if (object_)
		bpf_object__close(object_);
	object_	   = nullptr;
	stages_fd_ = state_fd_ = stats_fd_ = addrs_fd_ = ifinfo_fd_ = normal_fd_ = -1;
}

void Shaper::shutdown()
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (!ready_)
		return;
	ready_ = false;
	// Stop stamping first, then let packets that are already waiting in fq leave before the qdisc is replaced.
	for (Interface& iface : interfaces_)
	{
		if (iface.link)
			bpf_link__destroy(iface.link);
		iface.link = nullptr;
	}
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kDrainTimeoutMs);
	for (const Interface& iface : interfaces_)
	{
		uint32_t	queued = 0;
		std::string error;
		while (qdisc::queued_packets(iface.info.index, queued, error) && queued != 0 && std::chrono::steady_clock::now() < deadline)
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		if (queued != 0)
			LOG_WARN("%u delayed packet(s) on %s are dropped when its qdisc is restored", queued, iface.name.c_str());
	}
	rollback();
	LOG_DEBUG("kernel shaping shut down");
}

bool Shaper::fill_normal_scores()
{
	const auto scores = shaping::normal_scores();
	for (uint32_t index = 0; index < scores.size(); ++index)
		if (bpf_map_update_elem(normal_fd_, &index, &scores[index], BPF_ANY) != 0)
			return false;
	return true;
}

bool Shaper::add_sets(const std::vector<shaping::AddressSet>& sets, std::string& error)
{
	std::vector<lagsw_addr_key> added;
	for (const shaping::AddressSet& set : sets)
	{
		for (const uint32_t address : set.addrs)
		{
			lagsw_addr_key key{set.id, htonl(address)};
			const uint8_t  present = 1;
			if (bpf_map_update_elem(addrs_fd_, &key, &present, BPF_ANY) != 0)
			{
				error = "cannot store the address lists of the filter in the eBPF map: " + errno_text(errno);
				for (const lagsw_addr_key& done : added)
					bpf_map_delete_elem(addrs_fd_, &done);
				return false;
			}
			added.push_back(key);
		}
	}
	return true;
}

void Shaper::remove_sets(const std::vector<shaping::AddressSet>& sets)
{
	for (const shaping::AddressSet& set : sets)
		for (const uint32_t address : set.addrs)
		{
			lagsw_addr_key key{set.id, htonl(address)};
			bpf_map_delete_elem(addrs_fd_, &key);
		}
}

bool Shaper::write_stage(uint32_t slot, const lagsw_stage& stage, std::string& error)
{
	if (stages_fd_ < 0)
	{
		error = "kernel shaping is shut down";
		return false;
	}
	if (bpf_map_update_elem(stages_fd_, &slot, &stage, BPF_ANY) != 0)
	{
		error = "cannot write the eBPF stage: " + errno_text(errno);
		return false;
	}
	return true;
}

bool Shaper::reset_state(uint32_t slot)
{
	if (state_fd_ < 0)
		return false;
	const lagsw_state zero{};
	return bpf_map_update_elem(state_fd_, &slot, &zero, BPF_ANY) == 0;
}

backend::ShapeStats Shaper::read_stats(uint32_t slot)
{
	backend::ShapeStats total;
	if (stats_fd_ < 0)
		return total;
	std::vector<lagsw_stats> per_cpu(static_cast<size_t>(cpu_count_));
	if (bpf_map_lookup_elem(stats_fd_, &slot, per_cpu.data()) != 0)
		return total;
	for (const lagsw_stats& cpu : per_cpu)
	{
		total.matched += cpu.matched;
		total.delayed += cpu.delayed;
		total.dropped += cpu.dropped;
		total.clamped += cpu.clamped;
	}
	return total;
}

void Shaper::release(uint32_t slot, const std::vector<shaping::AddressSet>& sets)
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (stages_fd_ >= 0)
	{
		const lagsw_stage empty{};
		bpf_map_update_elem(stages_fd_, &slot, &empty, BPF_ANY);
		remove_sets(sets);
	}
	used_[slot] = false;
}

std::string Shaper::status()
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (!ready_)
		return {};
	backend::ShapeStats total;
	uint32_t			stages = 0;
	for (uint32_t slot = 0; slot < LAGSW_MAX_STAGES; ++slot)
	{
		if (!used_[slot])
			continue;
		++stages;
		const backend::ShapeStats stats = read_stats(slot);
		total.matched += stats.matched;
		total.delayed += stats.delayed;
		total.dropped += stats.dropped;
		total.clamped += stats.clamped;
	}
	return "bpf: " + std::to_string(stages) + " stage(s) on " + std::to_string(interfaces_.size()) + " iface(s), matched " + std::to_string(total.matched) + " delayed " +
		   std::to_string(total.delayed) + " dropped " + std::to_string(total.dropped);
}
}  // namespace

void configure(const backend::ShapingConfig& config)
{
	Shaper::instance().configure(config);
}

std::unique_ptr<backend::ShapeStage> open_stage(const backend::ShapeSpec& spec, std::string& reason)
{
	return Shaper::instance().open(spec, reason);
}

std::string status_text()
{
	return Shaper::instance().status();
}

}  // namespace nfq::shaper
