#include "qdisc.h"

#include <net/if.h>

#include <libmnl/libmnl.h>
#include <linux/gen_stats.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <memory>
#include <vector>

#ifndef NETLINK_EXT_ACK
#	define NETLINK_EXT_ACK 11
#endif

namespace nfq::qdisc {
namespace {
	constexpr int kReplyTimeoutMs = 5000;

	struct SocketCloser
	{
		void operator()(mnl_socket* socket) const { mnl_socket_close(socket); }
	};
	using Socket = std::unique_ptr<mnl_socket, SocketCloser>;

	Socket open_route_socket(std::string& error)
	{
		Socket socket(mnl_socket_open2(NETLINK_ROUTE, SOCK_CLOEXEC));
		if (!socket || mnl_socket_bind(socket.get(), 0, MNL_SOCKET_AUTOPID) < 0)
		{
			error = std::string("cannot open a routing netlink socket: ") + std::strerror(errno);
			return nullptr;
		}
		const int enable = 1;
		mnl_socket_setsockopt(socket.get(), NETLINK_EXT_ACK, const_cast<int*>(&enable), sizeof(enable));
		return socket;
	}

	std::string ack_message(const nlmsghdr* header, const nlmsgerr* error)
	{
		if ((header->nlmsg_flags & NLM_F_ACK_TLVS) == 0)
			return {};
		size_t offset = sizeof(nlmsgerr);
		if ((header->nlmsg_flags & NLM_F_CAPPED) == 0)
			offset += mnl_nlmsg_get_payload_len(&error->msg);
		const size_t payload = mnl_nlmsg_get_payload_len(header);
		if (offset >= payload)
			return {};
		const char* cursor = reinterpret_cast<const char*>(error) + offset;
		size_t		left   = payload - offset;
		while (left >= sizeof(nlattr))
		{
			const nlattr* attribute = reinterpret_cast<const nlattr*>(cursor);
			if (attribute->nla_len < sizeof(nlattr) || attribute->nla_len > left)
				break;
			if ((attribute->nla_type & NLA_TYPE_MASK) == NLMSGERR_ATTR_MSG)
				return std::string(cursor + NLA_HDRLEN, ::strnlen(cursor + NLA_HDRLEN, attribute->nla_len - NLA_HDRLEN));
			const size_t step = NLA_ALIGN(attribute->nla_len);
			if (step >= left)
				break;
			cursor += step;
			left -= step;
		}
		return {};
	}

	/// Sends one request and feeds every reply message to `visit` until the acknowledgement (or the end of a dump) arrives.
	/// `visit` returns false to stop early. Fills `error` and returns false when the kernel reports a failure.
	template<typename Visitor>
	bool transact(nlmsghdr* request, Visitor visit, std::string& error)
	{
		Socket socket = open_route_socket(error);
		if (!socket)
			return false;
		const uint32_t sequence = static_cast<uint32_t>(std::time(nullptr));
		request->nlmsg_seq		= sequence;
		if (mnl_socket_sendto(socket.get(), request, request->nlmsg_len) < 0)
		{
			error = std::string("netlink send failed: ") + std::strerror(errno);
			return false;
		}
		std::vector<char> buffer(MNL_SOCKET_BUFFER_SIZE * 4);
		pollfd			  descriptor{mnl_socket_get_fd(socket.get()), POLLIN, 0};
		for (;;)
		{
			const int ready = ::poll(&descriptor, 1, kReplyTimeoutMs);
			if (ready < 0 && errno == EINTR)
				continue;
			if (ready <= 0)
			{
				error = "timed out waiting for the kernel to answer";
				return false;
			}
			ssize_t received = mnl_socket_recvfrom(socket.get(), buffer.data(), buffer.size());
			if (received < 0)
			{
				if (errno == EINTR)
					continue;
				error = std::string("netlink receive failed: ") + std::strerror(errno);
				return false;
			}
			int length = static_cast<int>(received);
			for (const nlmsghdr* header = reinterpret_cast<const nlmsghdr*>(buffer.data()); mnl_nlmsg_ok(header, length);
				 header					= mnl_nlmsg_next(header, &length))
			{
				if (header->nlmsg_seq != sequence)
					continue;
				if (header->nlmsg_type == NLMSG_DONE)
					return true;
				if (header->nlmsg_type == NLMSG_ERROR)
				{
					if (mnl_nlmsg_get_payload_len(header) < sizeof(nlmsgerr))
						continue;
					const nlmsgerr* failure = static_cast<const nlmsgerr*>(mnl_nlmsg_get_payload(header));
					if (failure->error == 0)
						return true;
					error					 = std::strerror(-failure->error);
					const std::string detail = ack_message(header, failure);
					if (!detail.empty())
						error += ": " + detail;
					return false;
				}
				if (!visit(header))
					return true;
			}
		}
	}

	/// Calls `visit(attribute)` for each attribute after the header; stops when it returns false.
	template<typename Visitor>
	void for_each_attribute(const nlmsghdr* header, size_t offset, Visitor&& visit)
	{
		mnl_attr_parse(
			header,
			static_cast<unsigned>(offset),
			[](const nlattr* attribute, void* data) { return (*static_cast<Visitor*>(data))(attribute) ? MNL_CB_OK : MNL_CB_STOP; },
			&visit);
	}

	template<typename Visitor>
	void for_each_nested(const nlattr* nest, Visitor&& visit)
	{
		mnl_attr_parse_nested(
			nest,
			[](const nlattr* attribute, void* data) { return (*static_cast<Visitor*>(data))(attribute) ? MNL_CB_OK : MNL_CB_STOP; },
			&visit);
	}

	struct Message
	{
		std::vector<char> buffer = std::vector<char>(MNL_SOCKET_BUFFER_SIZE);
		nlmsghdr*		  header = nullptr;
		tcmsg*			  tc	 = nullptr;

		Message(uint16_t type, uint16_t flags, uint32_t ifindex, uint32_t parent, uint32_t handle)
		{
			header				= mnl_nlmsg_put_header(buffer.data());
			header->nlmsg_type	= type;
			header->nlmsg_flags = NLM_F_REQUEST | flags;
			tc					= static_cast<tcmsg*>(mnl_nlmsg_put_extra_header(header, sizeof(tcmsg)));
			tc->tcm_family		= AF_UNSPEC;
			tc->tcm_ifindex		= static_cast<int>(ifindex);
			tc->tcm_parent		= parent;
			tc->tcm_handle		= handle;
		}
	};

	std::string link_type_text(unsigned type)
	{
		return std::to_string(type);
	}
}  // namespace

bool resolve_interface(const std::string& name, Interface& out, std::string& error)
{
	if (name.empty() || name.size() >= IFNAMSIZ)
	{
		error = "invalid interface name '" + name + "'";
		return false;
	}
	const unsigned index = ::if_nametoindex(name.c_str());
	if (index == 0)
	{
		error = "interface '" + name + "' does not exist";
		return false;
	}
	unsigned	  type = 0;
	std::ifstream file("/sys/class/net/" + name + "/type");
	if (!(file >> type))
	{
		error = "cannot read the link type of interface '" + name + "'";
		return false;
	}
	out.index = index;
	if (type == ARPHRD_ETHER)
		out.l2_len = 14;
	else if (type == ARPHRD_NONE || type == ARPHRD_RAWIP)
		out.l2_len = 0;
	else
	{
		error = "interface '" + name + "' has link type " + link_type_text(type) + ", which the egress program cannot parse";
		return false;
	}
	return true;
}

bool root_kind(uint32_t ifindex, std::string& kind, std::string& error)
{
	Message	   request(RTM_GETQDISC, NLM_F_DUMP, ifindex, 0, 0);
	bool	   found = false;
	const bool ok	 = transact(
		request.header,
		[&](const nlmsghdr* header) {
			if (header->nlmsg_type != RTM_NEWQDISC || mnl_nlmsg_get_payload_len(header) < sizeof(tcmsg))
				return true;
			const tcmsg* tc = static_cast<const tcmsg*>(mnl_nlmsg_get_payload(header));
			if (tc->tcm_parent != TC_H_ROOT || static_cast<uint32_t>(tc->tcm_ifindex) != ifindex)
				return true;
			for_each_attribute(header, sizeof(tcmsg), [&](const nlattr* attribute) {
				if (mnl_attr_get_type(attribute) != TCA_KIND)
					return true;
				kind  = mnl_attr_get_str(attribute);
				found = true;
				return false;
			});
			return !found;
		},
		error);
	if (ok && !found)
		error = "the interface has no root qdisc";
	return ok && found;
}

bool replaceable_kind(const std::string& kind)
{
	return kind == "noqueue" || kind == "pfifo_fast" || kind == "fq_codel" || kind == "mq" || kind == "fq";
}

bool install_fq(uint32_t ifindex, const FqParameters& parameters, std::string& error)
{
	Message request(RTM_NEWQDISC, NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, ifindex, TC_H_ROOT, 0);
	mnl_attr_put_strz(request.header, TCA_KIND, "fq");
	nlattr* options = mnl_attr_nest_start(request.header, TCA_OPTIONS);
	mnl_attr_put_u32(request.header, TCA_FQ_PLIMIT, parameters.packet_limit);
	mnl_attr_put_u32(request.header, TCA_FQ_FLOW_PLIMIT, parameters.flow_packet_limit);
	mnl_attr_put_u32(request.header, TCA_FQ_HORIZON, parameters.horizon_ms * 1000u);
	mnl_attr_put_u8(request.header, TCA_FQ_HORIZON_DROP, 0);
	mnl_attr_nest_end(request.header, options);
	return transact(request.header, [](const nlmsghdr*) { return true; }, error);
}

bool restore(uint32_t ifindex, const std::string& kind, std::string& error)
{
	if (kind == "noqueue")
	{
		Message request(RTM_DELQDISC, NLM_F_ACK, ifindex, TC_H_ROOT, 0);
		return transact(request.header, [](const nlmsghdr*) { return true; }, error);
	}
	Message request(RTM_NEWQDISC, NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE, ifindex, TC_H_ROOT, 0);
	mnl_attr_put_strz(request.header, TCA_KIND, kind.c_str());
	return transact(request.header, [](const nlmsghdr*) { return true; }, error);
}

bool queued_packets(uint32_t ifindex, uint32_t& packets, std::string& error)
{
	Message	   request(RTM_GETQDISC, NLM_F_DUMP, ifindex, 0, 0);
	bool	   found = false;
	const bool ok	 = transact(
		request.header,
		[&](const nlmsghdr* header) {
			if (header->nlmsg_type != RTM_NEWQDISC || mnl_nlmsg_get_payload_len(header) < sizeof(tcmsg))
				return true;
			const tcmsg* tc = static_cast<const tcmsg*>(mnl_nlmsg_get_payload(header));
			if (tc->tcm_parent != TC_H_ROOT || static_cast<uint32_t>(tc->tcm_ifindex) != ifindex)
				return true;
			for_each_attribute(header, sizeof(tcmsg), [&](const nlattr* attribute) {
				if (mnl_attr_get_type(attribute) != TCA_STATS2)
					return true;
				for_each_nested(attribute, [&](const nlattr* stat) {
					if (mnl_attr_get_type(stat) == TCA_STATS_QUEUE && mnl_attr_get_payload_len(stat) >= sizeof(gnet_stats_queue))
					{
						packets = static_cast<const gnet_stats_queue*>(mnl_attr_get_payload(stat))->qlen;
						found	= true;
					}
					return true;
				});
				return true;
			});
			return !found;
		},
		error);
	if (ok && !found)
		error = "the qdisc reports no queue statistics";
	return ok && found;
}

}  // namespace nfq::qdisc
