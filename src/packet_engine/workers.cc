#include "internal.h"

#include "log.h"

void PacketEngine::start_workers()
{
	if (options_.resolve_region)
		resolve_client_region();
	if (options_.discovery_port)
	{
		const uint16_t	  port	 = *options_.discovery_port;
		const std::string filter = backend::filters::port(port);
		backend::OpenOptions open_options;
		open_options.filter = filter;
		open_options.sniff	= true;
		open_options.include_forward = true;
		std::string open_error;
		LOG_DEBUG("Server discovery setup: opening sniff channel with filter '%s'", filter.c_str());
		state_->discovery_handle = backend::open(open_options, open_error);
		if (!state_->discovery_handle)
		{
			LOG_ERROR("Server discovery setup: failed to open capture channel: %s", open_error.c_str());
		}
		else
		{
			LOG_INFO("Server discovery enabled on port %u with a %s window",
					 port,
					 logging::format_duration(options_.discovery_window_ms).c_str());
			state_->discovery_thread = std::thread(&PacketEngine::discover_packets, this);
		}
	}

	if (options_.features.region_enforcement.enabled && options_.features.region_enforcement.probe_port != 0)
	{
		const uint16_t	  port	 = options_.features.region_enforcement.probe_port;
		const std::string filter = backend::filters::syn_probe(port);
		backend::OpenOptions open_options;
		open_options.filter			 = filter;
		open_options.sniff			 = true;
		open_options.include_forward = true;
		std::string open_error;
		state_->probe_handle = backend::open(open_options, open_error);
		if (!state_->probe_handle)
		{
			LOG_ERROR("Probe detection setup: failed to open capture channel: %s", open_error.c_str());
		}
		else
		{
			LOG_INFO("Probe detection enabled on port %u", port);
			state_->probe_thread = std::thread(&PacketEngine::probe_packets, this);
		}

		start_region_enforcement();
	}

	if (options_.features.forwarded_address_discovery.enabled)
	{
		const uint32_t	  inbound_if_idx  = *options_.features.forwarded_address_discovery.inbound_if_idx;
		const uint32_t	  outbound_if_idx = *options_.features.forwarded_address_discovery.outbound_if_idx;
		const uint16_t	  port			  = options_.features.forwarded_address_discovery.port;
		const std::string filter		  = backend::filters::forwarded_address(inbound_if_idx, outbound_if_idx, port);
		LOG_DEBUG("Forwarded address discovery setup: opening filter '%s'", filter.c_str());
		// a dedicated priority avoids losing packets to other priority-0 handles (server discovery, profiles) with overlapping filters
		backend::OpenOptions open_options;
		open_options.filter	  = filter;
		open_options.sniff	  = true;
		open_options.priority = 1000;
		std::string open_error;
		state_->fad_handle = backend::open(open_options, open_error);
		if (!state_->fad_handle)
		{
			LOG_ERROR("Forwarded address discovery setup: failed to open capture channel: %s", open_error.c_str());
		}
		else
		{
			LOG_INFO("Forwarded address discovery enabled (inbound ifIdx %u, outbound ifIdx %u)", inbound_if_idx, outbound_if_idx);
			state_->fad_thread = std::thread(&PacketEngine::forwarded_address_discovery_recv, this);
		}
	}
}

void PacketEngine::stop_workers()
{
	shutdown_ = true;
	if (state_->discovery_handle)
		state_->discovery_handle->shutdown_recv();
	if (state_->probe_handle)
		state_->probe_handle->shutdown_recv();
	if (state_->fad_handle)
		state_->fad_handle->shutdown_recv();
	stop_region_enforcement();
	teardown();
	for (std::thread& cleanup_thread : state_->cleanup_threads)
		if (cleanup_thread.joinable())
			cleanup_thread.join();
	if (state_->discovery_thread.joinable())
		state_->discovery_thread.join();
	if (state_->probe_thread.joinable())
		state_->probe_thread.join();
	if (state_->fad_thread.joinable())
		state_->fad_thread.join();
	for (std::thread& region_thread : state_->region_threads)
		if (region_thread.joinable())
			region_thread.join();
	state_->region_threads.clear();
	for (auto* channel : {&state_->discovery_handle, &state_->probe_handle, &state_->fad_handle})
		if (*channel)
		{
			(*channel)->close();
			channel->reset();
		}
}
