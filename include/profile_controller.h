#ifndef PROFILE_CONTROLLER_H_
#define PROFILE_CONTROLLER_H_

#include <cstdint>
#include <vector>

#include "packet_engine.h"

/// Turns the state of the profiles' activation keys into engine calls: activating, toggling and deactivating profiles,
/// honoring disable waits, activation periods and mutually exclusive profiles.
class ProfileController
{
public:
	/// Both arguments must outlive the controller.
	ProfileController(PacketEngine& engine, const PacketEngineOptions& options);

	/// Polls the activation keys once and applies the resulting changes to the engine. Call it repeatedly.
	void update();

private:
	bool running(size_t index) const;
	bool send_key_down(size_t index) const;
	bool disables(size_t source, size_t target) const;
	bool has_active_disable_target(size_t source) const;
	bool all_shared_profiles_running(size_t index) const;
	bool shared_group_has_new_activation(size_t index) const;
	std::vector<bool> find_active_profiles() const;

	void setup_profile(size_t index);
	void schedule_teardown(size_t target, bool immediate);
	void disable_targets(size_t source);

	void end_expired_periods(uint64_t now);
	void end_expired_disable_waits(uint64_t now);
	void activate_pending_profiles();
	void find_switch_profiles();
	void apply_switches();
	void update_profile(size_t index);
	void update_hold_profile(size_t index);
	void update_toggle_profile(size_t index);

	PacketEngine&			   engine_;
	const PacketEngineOptions& options_;

	// State carried from one update() to the next.
	std::vector<bool>	  activation_key_held_;
	std::vector<bool>	  send_key_held_;
	std::vector<bool>	  pending_activation_;
	std::vector<uint64_t> disable_at_;
	std::vector<uint64_t> period_deactivate_at_;

	// State recomputed at the start of every update().
	std::vector<bool> active_profiles_;
	std::vector<bool> disabled_profiles_;
	std::vector<bool> shared_profiles_running_;
	std::vector<bool> shared_group_activated_;
	std::vector<bool> switch_profiles_;
};

#endif
