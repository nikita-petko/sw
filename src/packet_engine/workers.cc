#include "internal.h"

void PacketEngine::start_workers()
{
	if (options_.resolve_region)
		resolve_client_region();
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	if (options_.features.server_discovery.enabled)
		start_discovery_worker();
#endif
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	if (options_.features.region_enforcement.enabled && options_.features.region_enforcement.probe_port != 0)
		start_probe_worker();
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	if (options_.features.forwarded_address_discovery.enabled)
		start_forwarded_address_worker();
#endif
}

void PacketEngine::stop_workers()
{
	shutdown_ = true;
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	if (state_->discovery_handle)
		state_->discovery_handle->shutdown_recv();
#endif
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	if (state_->probe_handle)
		state_->probe_handle->shutdown_recv();
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	if (state_->fad_handle)
		state_->fad_handle->shutdown_recv();
#endif
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	stop_region_enforcement();
#endif
	teardown();
	for (std::thread& cleanup_thread : state_->cleanup_threads)
		if (cleanup_thread.joinable())
			cleanup_thread.join();
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	if (state_->discovery_thread.joinable())
		state_->discovery_thread.join();
#endif
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	if (state_->probe_thread.joinable())
		state_->probe_thread.join();
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	if (state_->fad_thread.joinable())
		state_->fad_thread.join();
#endif
	for (std::thread& region_thread : state_->region_threads)
		if (region_thread.joinable())
			region_thread.join();
	state_->region_threads.clear();
	[[maybe_unused]] const auto close_channel = [](std::unique_ptr<backend::PacketChannel>& channel) {
		if (channel)
		{
			channel->close();
			channel.reset();
		}
	};
#ifdef LAGSW_FEATURE_SERVER_DISCOVERY
	close_channel(state_->discovery_handle);
#endif
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	close_channel(state_->probe_handle);
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	close_channel(state_->fad_handle);
#endif
}
