#include "internal.h"

#include "log.h"

LOG_DEFAULT_GROUP(logging::group::discovery)

void PacketEngine::start_workers()
{
	if (options_.resolve_region)
		resolve_client_region();
	if (options_.discovery_port)
		start_discovery_worker();
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	if (options_.features.region_enforcement.enabled && options_.features.region_enforcement.probe_port != 0)
		start_probe_worker();
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	if (options_.features.forwarded_address_discovery.enabled)
		start_forwarded_address_worker();
#endif
}

void PacketEngine::start_discovery_worker()
{
	const uint16_t	  port	 = *options_.discovery_port;
	const std::string filter = backend::filters::port(port);
	backend::OpenOptions open_options;
	open_options.filter = filter;
	open_options.sniff	= true;
	open_options.include_forward = true;
	std::string open_error;
	LOG_DEBUG_GROUP(logging::group::discovery, "Server discovery setup: opening sniff channel with filter '%s'", filter.c_str());
	state_->discovery_handle = backend::open(open_options, open_error);
	if (!state_->discovery_handle)
	{
		LOG_ERROR("Server discovery setup: failed to open capture channel: %s", open_error.c_str());
		return;
	}
	LOG_INFO("Server discovery enabled on port %u with a %s window",
			 port,
			 logging::format_duration(options_.discovery_window_ms).c_str());
	state_->discovery_thread = std::thread(&PacketEngine::discover_packets, this);
}

void PacketEngine::stop_workers()
{
	shutdown_ = true;
	if (state_->discovery_handle)
		state_->discovery_handle->shutdown_recv();
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
	if (state_->discovery_thread.joinable())
		state_->discovery_thread.join();
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
	const auto close_channel = [](std::unique_ptr<backend::PacketChannel>& channel) {
		if (channel)
		{
			channel->close();
			channel.reset();
		}
	};
	close_channel(state_->discovery_handle);
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	close_channel(state_->probe_handle);
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	close_channel(state_->fad_handle);
#endif
}
