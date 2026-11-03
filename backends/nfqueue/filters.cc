// Builders for the capture filter expressions the engine needs (backend::filters). The expressions are in the syntax the NFQUEUE
// backend's compiler reads, which the swdivert kernel-module backend (backends/kmod) reads as well, so both link this file.
#include <string>
#include <vector>

#include "packet_backend.h"

namespace backend {
namespace {
	std::string address_chain(const char* field, const std::vector<std::string>& addresses)
	{
		std::string chain;
		for (const std::string& address : addresses)
		{
			if (!chain.empty())
				chain += " or ";
			chain += field + std::string(" == ") + address;
		}
		return chain;
	}

	std::string port_expression(uint16_t port)
	{
		const std::string text = std::to_string(port);
		return "tcp.DstPort == " + text + " or tcp.SrcPort == " + text + " or udp.DstPort == " + text + " or udp.SrcPort == " + text;
	}
}  // namespace

namespace filters {
	std::string profile(const ProfileFilter& spec)
	{
		std::string filter = spec.user_filter;
		if (spec.include_bare_acks)
			filter = "(" + filter + ") or (tcp.Ack and not tcp.Psh)";

		std::string client_filter;
		if (spec.client_enforcement == ClientAddressEnforcement::source || spec.client_enforcement == ClientAddressEnforcement::both)
			if (spec.client_source)
				client_filter = "ip.SrcAddr == " + *spec.client_source;
		if (spec.client_enforcement == ClientAddressEnforcement::destination || spec.client_enforcement == ClientAddressEnforcement::both)
			if (spec.client_destination)
			{
				if (!client_filter.empty())
					client_filter += " or ";
				client_filter += "ip.DstAddr == " + *spec.client_destination;
			}
		if (!client_filter.empty())
			filter = "(" + filter + ") and (" + client_filter + ")";

		if (spec.server_direction && !spec.server_addresses.empty())
		{
			const char* address_field = "ip.Addr";
			switch (*spec.server_direction)
			{
				case ServerDirection::source:
					address_field = "ip.SrcAddr";
					break;
				case ServerDirection::destination:
					address_field = "ip.DstAddr";
					break;
				case ServerDirection::both:
					break;
			}
			filter = "(" + filter + ") and (" + address_chain(address_field, spec.server_addresses) + ")";
		}
		return spec.outbound ? "outbound and (" + filter + ")" : filter;
	}

	std::string port(uint16_t port)
	{
		return port_expression(port);
	}

#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	std::string syn_probe(uint16_t port)
	{
		const std::string text = std::to_string(port);
		return "tcp.Syn and (tcp.DstPort == " + text + " or tcp.SrcPort == " + text + ")";
	}

	std::string region_enforcement(const std::vector<std::string>& server_addresses, uint16_t port)
	{
		if (server_addresses.empty())
			return {};
		return "tcp.Psh and (" + address_chain("ip.SrcAddr", server_addresses) + ") and tcp.SrcPort == " + std::to_string(port);
	}
#endif

#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	std::string forwarded_address(uint32_t inbound_if_index, uint32_t outbound_if_index, uint16_t port)
	{
		return "outbound and (ifIdx == " + std::to_string(inbound_if_index) + " or ifIdx == " + std::to_string(outbound_if_index) +
			   ") and (" + port_expression(port) + ")";
	}
#endif
}  // namespace filters
}  // namespace backend
