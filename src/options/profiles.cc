#include <algorithm>
#include <fstream>
#include <functional>
#include <limits>
#include <string>
#include <unordered_map>

#include "internal.h"
#include "log.h"

namespace config {
namespace {
constexpr unsigned long kMaxPort = (std::numeric_limits<uint16_t>::max)();
constexpr unsigned long kMaxU32	 = (std::numeric_limits<uint32_t>::max)();
constexpr long			kMaxI32	 = (std::numeric_limits<int32_t>::max)();
/// Name of the open `enabled_for:` list while a feature's settings are being read.
constexpr const char*	kEnabledForList = "enabled_for";

/// Outcome of offering a line to one of the parser's handlers.
enum class Status
{
	unhandled,
	ok,
	error,
};

Status to_status(bool ok)
{
	return ok ? Status::ok : Status::error;
}

/// Calls `visit` with each comma separated piece of `list` (without any brackets); stops when `visit` returns false.
bool for_each_piece(const std::string& list, const std::function<bool(const std::string&)>& visit)
{
	for (size_t start = 0; start < list.size();)
	{
		const size_t end = list.find(',', start);
		if (!visit(list.substr(start, end == std::string::npos ? std::string::npos : end - start)))
			return false;
		if (end == std::string::npos)
			break;
		start = end + 1;
	}
	return true;
}

/// Calls `visit` with each trimmed item of an inline list written as "[a, b]", "a, b" or "a".
bool for_each_item(const std::string& value, const std::function<bool(const std::string&)>& visit)
{
	std::string list = trim(value);
	if (list.size() >= 2 && list.front() == '[' && list.back() == ']')
		list = list.substr(1, list.size() - 2);
	else if (list.empty())
		return true;
	else
		list += ',';
	return for_each_piece(list, [&](const std::string& piece) { return visit(trim(piece)); });
}

bool add_keys(const Context& context, const std::string& value, ProfileOptions& profile)
{
	return for_each_item(value, [&](const std::string& item) {
		const auto key = parse_key(item);
		if (!key)
			return invalid(context, "profile key");
		if (*key == kTabKey)
		{
			LOG_ERROR("Tab is reserved for printing packet engine state in %s at line %d", context.path, context.line);
			return false;
		}
		profile.keys.push_back(*key);
		return true;
	});
}

/// Appends the unquoted, non-empty items of an inline list of profile names.
bool add_names(const Context& context, const std::string& value, std::vector<std::string>& names, const char* what)
{
	return for_each_item(value, [&](const std::string& raw) {
		const std::string item = unquote(raw);
		if (item.empty())
			return invalid(context, what);
		names.push_back(item);
		return true;
	});
}

bool add_server(const Context& context, const std::string& value, PacketEngineOptions& options, const std::string& group)
{
	const std::string item = unquote(trim(value));
	if (item.empty())
		return invalid(context, "empty server");
	const size_t  separator = item.find(':');
	ServerOptions server;
	server.address = trim(item.substr(0, separator));
	server.name	   = separator == std::string::npos ? server.address : trim(item.substr(separator + 1));
	server.group   = group;
	if (server.address.empty() || server.name.empty())
		return invalid(context, "server '" + item + "'", "; expected address or address:name");
	const bool known = std::any_of(options.servers.begin(), options.servers.end(), [&](const ServerOptions& existing) {
		return existing.address == server.address;
	});
	if (!known)
		options.servers.push_back(server);
	return true;
}

bool assign_bool(const Context& context, const std::string& value, bool& out, const char* what = "boolean")
{
	const auto parsed = parse_bool(unquote(value));
	if (!parsed)
		return invalid(context, what);
	out = *parsed;
	return true;
}

/// Stores the unquoted value parsed by `parse` into `out`, which may be an optional.
template <typename Out, typename Parser>
bool assign_enum(const Context& context, const std::string& value, Parser parse, Out& out, const char* what, const char* expected)
{
	const auto parsed = parse(unquote(value));
	if (!parsed)
		return invalid(context, what, expected);
	out = *parsed;
	return true;
}

/// Stores a number parsed by one of the parse_* helpers into `out`, which may be an optional.
template <typename Target, typename Out, typename Parsed>
bool assign_number(const Context& context, const Parsed& parsed, Out& out, const std::string& what, const char* detail = "")
{
	if (!parsed)
		return invalid(context, what, detail);
	out = static_cast<Target>(*parsed);
	return true;
}

using ProfileSetter = bool (*)(const Context&, ProfileOptions&, const std::string&);

/// Setters for the plain `key: value` settings of a profile. Keys that are not listed are ignored.
const std::unordered_map<std::string, ProfileSetter>& profile_setters()
{
	static const std::unordered_map<std::string, ProfileSetter> setters = {
		{"name",
		 [](const Context&, ProfileOptions& profile, const std::string& value) {
			 profile.name = unquote(value);
			 return true;
		 }},
		{"key_mode",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_enum(context, value, parse_key_mode, profile.key_mode, "profile key_mode", ": expected oneof or combination");
		 }},
		{"mode",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_enum(context, value, parse_activation_mode, profile.mode, "profile mode", ": expected toggle, hold, or period");
		 }},
		{"delay_mode",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_enum(context,
								value,
								parse_delay_mode,
								profile.delay_mode,
								"delay_mode",
								": expected from_timestamp, send_all_after_delay, ratio, drop, drop_and_send, hold_and_send, "
								"drop_until_toggle, hold_until_deactivation, or packet_group_send");
		 }},
		{"retransmission_mode",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_enum(context,
								value,
								parse_retransmission_mode,
								profile.retransmission_mode,
								"retransmission_mode",
								": expected none, only_seq, only_ack, or both");
		 }},
		{"subsequent_packet_hold_mode",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_enum(context,
								value,
								parse_subsequent_packet_hold_mode,
								profile.subsequent_packet_hold_mode,
								"subsequent_packet_hold_mode",
								": expected none, seq_only, ack_only, or seq_ack");
		 }},
		{"ack_restoration",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_bool(context, value, profile.ack_restoration, "ack_restoration");
		 }},
		{"delay_ms",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 try
			 {
				 profile.delay_ms = static_cast<int32_t>(std::stol(value));
			 }
			 catch (...)
			 {
				 return invalid(context, "delay_ms");
			 }
			 return true;
		 }},
		{"disable_wait_ms",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_number<uint32_t>(context, parse_ulong(unquote(value), 0, kMaxU32), profile.disable_wait_ms, "disable_wait_ms");
		 }},
		{"activation_period",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 const std::string text = unquote(value);
			 if (text.empty() || text.front() == '-')
				 return invalid(context, "activation_period", ": expected positive milliseconds");
			 return assign_number<uint32_t>(context,
											parse_ulong(text, 1, kMaxU32),
											profile.activation_period_ms,
											"activation_period",
											": expected positive milliseconds");
		 }},
		{"disable_wait_percent",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_number<uint8_t>(context, parse_ulong(unquote(value), 0, 100), profile.disable_wait_percent, "disable_wait_percent");
		 }},
		{"respect_disable_wait",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_bool(context, value, profile.respect_disable_wait, "respect_disable_wait");
		 }},
		{"ratio",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 std::string text	 = trim(unquote(value));
			 const bool	 percent = !text.empty() && text.back() == '%';
			 if (percent)
				 text.pop_back();
			 if (!assign_number<int32_t>(context, parse_long(text, (std::numeric_limits<long>::min)(), (std::numeric_limits<long>::max)()), profile.ratio, "ratio"))
				 return false;
			 profile.ratio_percent	  = percent;
			 profile.ratio_configured = true;
			 return true;
		 }},
		{"amount",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_number<int32_t>(context, parse_long(unquote(value), 0, kMaxI32), profile.amount, "amount");
		 }},
		{"group_count",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_number<int32_t>(context, parse_long(unquote(value), 0, kMaxI32), profile.group_count, "group_count");
		 }},
		{"group_order",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_enum(context, value, parse_packet_group_order, profile.group_order, "group_order", ": expected fifo, lifo, or random");
		 }},
		{"ratio_selection",
		 [](const Context& context, ProfileOptions& profile, const std::string& value) {
			 return assign_enum(context, value, parse_ratio_selection, profile.ratio_selection, "ratio_selection", ": expected first, last, or random");
		 }},
		{"filter",
		 [](const Context&, ProfileOptions& profile, const std::string& value) {
			 profile.filter = unquote(value);
			 return true;
		 }},
	};
	return setters;
}

/// Reads the indentation-based subset of YAML used by profile files, one line at a time.
///
/// `section_` is the current top-level block (profiles, servers or features) and `subsection_` the nested block or list
/// being read. A nested line only belongs to its block while it is indented deeper than `subsection_indent_`.
class ProfilesParser
{
public:
	ProfilesParser(const char* path, PacketEngineOptions& options) : context_{path, 0}, options_(options) {}

	bool parse(std::istream& input)
	{
		std::string line;
		while (std::getline(input, line))
			if (!parse_line(line))
				return false;
		return true;
	}

private:
	bool parse_line(std::string line)
	{
		++context_.line;
		const int indent = static_cast<int>(line.find_first_not_of(" \t"));
		if (const auto comment = line.find('#'); comment != std::string::npos)
			line.erase(comment);
		const std::string content = trim(line);
		if (content.empty())
			return true;
		if (const Status status = parse_list_item(content, indent); status != Status::unhandled)
			return status == Status::ok;

		const auto colon = content.find(':');
		if (colon == std::string::npos)
			return invalid(context_, "YAML");
		const std::string key	= trim(content.substr(0, colon));
		const std::string value = trim(content.substr(colon + 1));
		leave_finished_lists(indent);
		if (features_base_ != -1 && section_ == "features" && indent > features_base_)
			return parse_feature(key, value, indent);
		if (servers_base_ != -1 && section_ != "profiles" && indent > servers_base_)
			return parse_server_setting(key, value, indent);
		if (const Status status = parse_structure(key, value, indent); status != Status::unhandled)
			return status == Status::ok;
		if (!profile_ || section_ != "profiles")
			return true;
		return parse_profile_setting(key, value, indent);
	}

	void clear_subsection()
	{
		subsection_.clear();
		subsection_indent_ = -1;
	}

	void enter_subsection(const std::string& name, int indent)
	{
		subsection_		   = name;
		subsection_indent_ = indent;
	}

	void enter_section(const std::string& name, int indent)
	{
		section_ = name;
		clear_subsection();
		servers_base_ = features_base_ = feature_indent_ = -1;
		feature_.clear();
		list_target_ = nullptr;
		if (name == "features")
			features_base_ = indent;
		else if (name == "servers")
		{
			servers_base_ = indent;
			enter_subsection("servers", indent);
		}
	}

	/// Handles a "- item" line of the list that is currently open (keys, disables, enabled_for lists, servers).
	Status parse_list_item(const std::string& content, int indent)
	{
		if (content.front() != '-')
			return Status::unhandled;
		const std::string item		  = content.substr(1);
		const bool		  plain_item  = content.find(':') == std::string::npos;
		const bool		  indented	  = indent > subsection_indent_;
		if (plain_item && subsection_ == "keys")
			return to_status(profile_ && indented && add_keys(context_, item, *profile_));
		if (plain_item && subsection_ == "disables")
			return to_status(profile_ && indented && add_names(context_, item, profile_->disables, "disabled profile"));
		if (plain_item && subsection_ == kEnabledForList)
			return to_status(indented && (!list_target_ || add_names(context_, item, *list_target_, list_what_)));
		if (subsection_ == "addresses" || subsection_ == "server_group")
			return to_status(indented && add_server(context_, item, options_, subsection_ == "server_group" ? server_group_ : ""));
		return Status::unhandled;
	}

	/// A key at or left of an enabled_for list's own key ends the list and returns to the feature's block.
	void leave_finished_lists(int indent)
	{
		if (subsection_ == kEnabledForList && indent <= subsection_indent_)
			enter_subsection(feature_, feature_indent_);
	}

	/// Opens the `enabled_for` list of the current feature; the values go to `target`, or nowhere when it is null.
	Status begin_enabled_for(const std::string& value, int indent, std::vector<std::string>* target, const char* what)
	{
		enter_subsection(kEnabledForList, indent);
		list_target_ = target;
		list_what_	 = what;
		return to_status(!target || add_names(context_, value, *target, what));
	}

	/// A feature section of the `features:` block, and how its keys are parsed.
	struct Feature
	{
		using Parser = Status (ProfilesParser::*)(const std::string& key, const std::string& value, int indent);

		Parser parse;
		/// False when the feature was left out of this build; its section is then ignored.
		bool compiled;
	};

	/// Maps every feature section to the function that parses its keys. Features that are not compiled into the build
	/// map to ignore_feature, so a profiles file can be shared between builds.
	static const std::unordered_map<std::string, Feature>& features()
	{
		[[maybe_unused]] static const Feature disabled{&ProfilesParser::ignore_feature, false};
		static const std::unordered_map<std::string, Feature> table = {
#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
			{"region_enforcement", {&ProfilesParser::parse_region_enforcement, true}},
#else
			{"region_enforcement", disabled},
#endif
#ifdef LAGSW_FEATURE_PCAP_FILES
			{"pcap_files", {&ProfilesParser::parse_pcap_files, true}},
#else
			{"pcap_files", disabled},
#endif
#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
			{"desync_countdown", {&ProfilesParser::parse_desync_countdown, true}},
#else
			{"desync_countdown", disabled},
#endif
#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
			{"forwarded_address_discovery", {&ProfilesParser::parse_forwarded_address_discovery, true}},
#else
			{"forwarded_address_discovery", disabled},
#endif
		};
		return table;
	}

	bool parse_feature(const std::string& key, const std::string& value, int indent)
	{
		const auto& table = features();
		if (value.empty())
		{
			if (const auto feature = table.find(key); feature != table.end())
			{
				feature_		= key;
				feature_indent_ = indent;
				enter_subsection(key, indent);
				if (!feature->second.compiled)
					LOG_WARN("Feature %s in %s at line %d is not compiled into this build; its settings are ignored",
							 key.c_str(),
							 context_.path,
							 context_.line);
				return true;
			}
		}
		if (indent > subsection_indent_)
		{
			if (const auto feature = table.find(subsection_); feature != table.end())
			{
				const Status status = (this->*feature->second.parse)(key, value, indent);
				if (status != Status::unhandled)
					return status == Status::ok;
			}
		}
		return invalid(context_, "features configuration key '" + key + "'");
	}

	/// Skips the settings of a feature that is not compiled into this build.
	Status ignore_feature(const std::string& key, const std::string& value, int indent)
	{
		if (key == "enabled_for")
			return begin_enabled_for(value, indent, nullptr, "");
		return Status::ok;
	}

#ifdef LAGSW_FEATURE_FORWARDED_ADDRESS_DISCOVERY
	Status parse_forwarded_address_discovery(const std::string& key, const std::string& value, int)
	{
		ForwardedAddressDiscoveryOptions& discovery = options_.features.forwarded_address_discovery;
		if (key == "enabled")
			return to_status(assign_bool(context_, value, discovery.enabled));
		if (key == "inbound")
			return to_status(assign_number<uint32_t>(
				context_, parse_ulong(unquote(value), 0, kMaxU32), discovery.inbound_if_idx, key + " interface index"));
		if (key == "outbound")
			return to_status(assign_number<uint32_t>(
				context_, parse_ulong(unquote(value), 0, kMaxU32), discovery.outbound_if_idx, key + " interface index"));
		if (key == "interval")
			return to_status(assign_number<uint64_t>(
				context_, parse_ullong(unquote(value), 1), discovery.window_ms, "forwarded_address_discovery interval"));
		if (key == "port")
			return to_status(assign_number<uint16_t>(
				context_, parse_ulong(unquote(value), 1, kMaxPort), discovery.port, "forwarded_address_discovery port"));
		return Status::unhandled;
	}
#endif

#ifdef LAGSW_FEATURE_REGION_ENFORCEMENT
	Status parse_region_enforcement(const std::string& key, const std::string& value, int)
	{
		RegionEnforcementOptions& region = options_.features.region_enforcement;
		if (key == "enabled")
			return to_status(assign_bool(context_, value, region.enabled));
		if (key == "probe_port")
			return to_status(assign_number<uint16_t>(context_, parse_ulong(unquote(value), 1, kMaxPort), region.probe_port, "probe_port"));
		return Status::unhandled;
	}
#endif

#ifdef LAGSW_FEATURE_PCAP_FILES
	Status parse_pcap_files(const std::string& key, const std::string& value, int indent)
	{
		PcapFilesOptions& pcap = options_.features.pcap_files;
		if (key == "enabled")
			return to_status(assign_bool(context_, value, pcap.enabled));
		if (key == "output_dir")
		{
			const std::string output_dir = unquote(value);
			if (output_dir.empty())
				return to_status(invalid(context_, "pcap_files output_dir"));
			pcap.output_dir = output_dir;
			return Status::ok;
		}
		if (key == "enabled_for")
			return begin_enabled_for(value, indent, &pcap.enabled_for, "pcap_files enabled_for value");
		return Status::unhandled;
	}
#endif

#ifdef LAGSW_FEATURE_DESYNC_COUNTDOWN
	Status parse_desync_countdown(const std::string& key, const std::string& value, int indent)
	{
		DesyncCountdownOptions& countdown = options_.features.desync_countdown;
		if (key == "enabled")
			return to_status(assign_bool(context_, value, countdown.enabled));
		if (key == "display")
		{
			const std::string mode = unquote(value);
			return to_status(assign_enum(context_, value, parse_countdown_display, countdown.display, ("desync_countdown display '" + mode + "'").c_str(), ""));
		}
		if (key == "duration_percent")
			return to_status(assign_number<uint8_t>(
				context_, parse_ulong(unquote(value), 1, 100), countdown.duration_percent, "desync_countdown duration_percent"));
		if (key == "enabled_for")
			return begin_enabled_for(value, indent, &countdown.enabled_for, "desync_countdown enabled_for value");
		return Status::unhandled;
	}
#endif

	/// Handles a setting inside the `servers:` block: discovery settings, address lists and named server groups.
	bool parse_server_setting(const std::string& key, const std::string& value, int indent)
	{
		if (key == "discovery_port")
			return assign_number<uint16_t>(context_, parse_ulong(unquote(value), 1, kMaxPort), options_.discovery_port, "discovery_port");
		if (key == "interval")
			return assign_number<uint64_t>(context_, parse_ullong(unquote(value), 1), options_.discovery_window_ms, "interval");
		if (key == "addresses")
		{
			if (value.empty())
			{
				enter_subsection("addresses", indent);
				return true;
			}
			const std::string list = trim(value);
			if (list.size() < 2 || list.front() != '[' || list.back() != ']')
				return invalid(context_, "servers addresses list");
			return for_each_piece(list.substr(1, list.size() - 2),
								  [&](const std::string& piece) { return add_server(context_, piece, options_, ""); });
		}
		if (value.empty())
		{
			enter_subsection("server_group", indent);
			server_group_ = unquote(key);
			return true;
		}
		return invalid(context_, "servers configuration key '" + key + "'");
	}

	/// Handles keys that open or switch blocks, start a profile, or set a key list.
	Status parse_structure(const std::string& key, const std::string& value, int indent)
	{
		if (key == "- name")
		{
			options_.profiles.push_back({});
			profile_	  = &options_.profiles.back();
			profile_->name = unquote(value);
			clear_subsection();
			return Status::ok;
		}
		if (value.empty() && (key == "features" || key == "profiles" || key == "servers"))
		{
			enter_section(key, indent);
			return Status::ok;
		}
		// `windivert_options` is the legacy name of `capture_options`
		if ((key == "capture_options" || key == "windivert_options") && value.empty() && profile_)
		{
			enter_subsection("capture_options", indent);
			return Status::ok;
		}
		if (key == "keys" && profile_)
		{
			enter_subsection("keys", indent);
			return to_status(add_keys(context_, value, *profile_));
		}
		if (key == "disables" && profile_)
		{
			enter_subsection("disables", indent);
			return to_status(add_names(context_, value, profile_->disables, "disabled profile"));
		}
		if (key == "key" && profile_)
		{
			clear_subsection();
			return to_status(add_keys(context_, value, *profile_));
		}
		if (key == "send_key" && profile_)
		{
			clear_subsection();
			ProfileOptions parsed;
			if (!add_keys(context_, value, parsed) || parsed.keys.size() != 1)
			{
				LOG_ERROR("send_key in %s at line %d must contain exactly one key", context_.path, context_.line);
				return Status::error;
			}
			profile_->send_key = parsed.keys.front();
			return Status::ok;
		}
		if (indent == 0 && key == "global_filter")
		{
			options_.global_filter = unquote(value);
			return Status::ok;
		}
		return Status::unhandled;
	}

	bool parse_profile_setting(const std::string& key, const std::string& value, int indent)
	{
		if (subsection_ == "capture_options" && indent > subsection_indent_)
			return parse_capture_option(key, value);
		clear_subsection();
		const auto setter = profile_setters().find(key);
		return setter == profile_setters().end() || setter->second(context_, *profile_, value);
	}

	bool parse_capture_option(const std::string& key, const std::string& value)
	{
		CaptureOptions& capture = profile_->capture_options;
		if (key == "server_direction")
			return assign_enum(context_,
							   value,
							   parse_server_direction,
							   capture.server_direction,
							   "server_direction",
							   ": expected source, destination, or both");
		if (key == "client_address_enforcement")
			return assign_enum(context_,
							   value,
							   parse_client_address_enforcement,
							   capture.client_address_enforcement,
							   "client_address_enforcement",
							   ": expected none, source, destination, or both");
		const auto parsed = parse_bool(value);
		if (!parsed)
			return invalid(context_, "boolean");
		if (key == "sniff")
			capture.sniff = *parsed;
		else if (key == "forward")
			capture.forward = *parsed;
		else if (key == "outbound")
			capture.outbound = *parsed;
		else
			clear_subsection();
		return true;
	}

	Context				 context_;
	PacketEngineOptions& options_;
	ProfileOptions*		 profile_ = nullptr;
	std::string			 section_;
	std::string			 subsection_;
	std::string			 server_group_;
	int					 subsection_indent_ = -1;
	int					 servers_base_		= -1;
	int					 features_base_		= -1;
	/// The feature section being read and the indentation of its key.
	std::string			 feature_;
	int					 feature_indent_	= -1;
	/// Destination of the open enabled_for list; null when the feature is not compiled into this build.
	std::vector<std::string>* list_target_	= nullptr;
	const char*			 list_what_			= "";
};
}  // namespace

bool load_profiles(const char* path, PacketEngineOptions& options)
{
	std::ifstream file(path);
	if (!file)
	{
		LOG_ERROR("Unable to open profiles file: %s", path);
		return false;
	}

	options.profiles.clear();
	options.servers.clear();
	options.discovery_port.reset();
	options.discovery_window_ms = 5000;
	options.features			= {};
	return ProfilesParser(path, options).parse(file) && validate_profiles(path, options);
}

}  // namespace config
