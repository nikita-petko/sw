#include "config_tui.h"

#ifdef LAGSW_FEATURE_CONFIG_TUI

#	include <algorithm>

namespace config_tui {
namespace {
	struct Frame
	{
		int			indent;
		std::string name;
		bool		item;
		int			next_item;
	};

	size_t scan_value_end(const std::string& line, size_t begin)
	{
		const size_t size = line.size();
		if (line[begin] == '"' || line[begin] == '\'')
		{
			const char quote = line[begin];
			size_t	   j	 = begin + 1;
			while (j < size)
			{
				if (quote == '"' && line[j] == '\\')
					j += 2;
				else if (line[j] == quote)
				{
					if (quote == '\'' && j + 1 < size && line[j + 1] == '\'')
						j += 2;
					else
						break;
				}
				else
					++j;
			}
			return (std::min)(j + 1, size);
		}
		size_t end = size;
		for (size_t j = begin + 1; j < size; ++j)
			if (line[j] == '#' && line[j - 1] == ' ')
			{
				end = j;
				break;
			}
		while (end > begin && (line[end - 1] == ' ' || line[end - 1] == '\r'))
			--end;
		return end;
	}

	std::string unquoted(std::string value)
	{
		if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') && value.back() == value.front())
			return value.substr(1, value.size() - 2);
		return value;
	}
}  // namespace

std::vector<OutlineEntry> build_outline(const std::vector<std::string>& lines)
{
	std::vector<OutlineEntry> outline;
	std::vector<Frame>		  stack{{-1, {}, false, 0}};

	const auto path_of = [&] {
		std::string path;
		for (size_t i = 1; i < stack.size(); ++i)
			path += stack[i].item ? stack[i].name : (path.empty() ? stack[i].name : "." + stack[i].name);
		return path;
	};
	const auto header = [&](size_t line, const std::string& path, const std::string& key) {
		OutlineEntry entry;
		entry.line	= line;
		entry.depth = static_cast<int>(stack.size()) - 1;
		entry.path	= path;
		entry.key	= key;
		outline.push_back(entry);
	};

	for (size_t index = 0; index < lines.size(); ++index)
	{
		const std::string& line	  = lines[index];
		const size_t	   indent = line.find_first_not_of(' ');
		if (indent == std::string::npos || line[indent] == '#' || line[indent] == '\r')
			continue;

		size_t position	  = indent;
		size_t key_indent = indent;
		bool   in_item	  = false;
		if (line[position] == '-' && (position + 1 == line.size() || line[position + 1] == ' '))
		{
			while (stack.size() > 1 &&
				   (stack.back().indent > static_cast<int>(indent) || (stack.back().indent == static_cast<int>(indent) && stack.back().item)))
				stack.pop_back();
			const std::string name = "[" + std::to_string(stack.back().next_item++) + "]";
			header(index, path_of() + name, name);
			stack.push_back({static_cast<int>(indent), name, true, 0});
			in_item			= true;
			const size_t after = line.find_first_not_of(' ', position + 1);
			if (after == std::string::npos || line[after] == '#')
				continue;
			position   = after;
			key_indent = after;
		}
		else
		{
			while (stack.size() > 1 && stack.back().indent >= static_cast<int>(indent))
				stack.pop_back();
		}

		size_t separator = std::string::npos;
		if (line[position] != '"' && line[position] != '\'' && line[position] != '[' && line[position] != '{')
			for (size_t j = position; j < line.size(); ++j)
			{
				if (line[j] == '#' && j > position && line[j - 1] == ' ')
					break;
				if (line[j] == ':' && (j + 1 == line.size() || line[j + 1] == ' ' || line[j + 1] == '\r'))
				{
					separator = j;
					break;
				}
			}

		OutlineEntry entry;
		entry.line = index;
		if (separator == std::string::npos)
		{
			if (!in_item)
				continue;
			// a plain list item such as `- "10.0.0.1:name"` is a leaf, not a header
			outline.pop_back();
			entry.depth		  = static_cast<int>(stack.size()) - 2;
			entry.leaf		  = true;
			entry.path		  = path_of();
			entry.key		  = stack.size() > 2 ? stack[stack.size() - 2].name : std::string();
			entry.value_begin = position;
			entry.value_end	  = scan_value_end(line, position);
			entry.value		  = line.substr(entry.value_begin, entry.value_end - entry.value_begin);
			outline.push_back(entry);
			continue;
		}

		std::string key = line.substr(position, separator - position);
		key.erase(key.find_last_not_of(' ') + 1);
		key							= unquoted(key);
		const size_t value_start	= line.find_first_not_of(' ', separator + 1);
		const std::string base		= path_of();
		const std::string full_path = base.empty() ? key : base + "." + key;
		if (value_start == std::string::npos || line[value_start] == '#' || line[value_start] == '\r')
		{
			header(index, full_path, key);
			stack.push_back({static_cast<int>(key_indent), key, false, 0});
			continue;
		}
		entry.depth		  = static_cast<int>(stack.size()) - 1;
		entry.leaf		  = true;
		entry.path		  = full_path;
		entry.key		  = key;
		entry.value_begin = value_start;
		entry.value_end	  = scan_value_end(line, value_start);
		entry.value		  = line.substr(entry.value_begin, entry.value_end - entry.value_begin);
		outline.push_back(entry);
	}
	return outline;
}

std::string replace_value(const std::string& line, const OutlineEntry& entry, const std::string& value)
{
	if (entry.value_begin > line.size() || entry.value_end > line.size() || entry.value_begin > entry.value_end)
		return line;
	return line.substr(0, entry.value_begin) + value + line.substr(entry.value_end);
}

std::vector<std::string> value_choices(const OutlineEntry& entry)
{
	if (!entry.leaf)
		return {};
	const std::string value = unquoted(entry.value);
	if (value == "true" || value == "false")
		return {"true", "false"};
	if (entry.key == "mode")
	{
		if (entry.path.rfind("profiles[", 0) == 0)
			return {"toggle", "hold", "period"};
		return {"fixed", "uniform", "normal"};
	}
	static const struct
	{
		const char*				 key;
		std::vector<std::string> values;
	} table[] = {
		{"default_view", {"log", "net_monitor"}},
		{"tier", {"auto", "nfqueue", "bpf"}},
		{"direction", {"both", "inbound", "outbound"}},
		{"display", {"alongside", "override", "until_reactivated"}},
		{"key_mode", {"combination", "oneof"}},
		{"delay_mode",
		 {"from_timestamp", "send_all_after_delay", "ratio", "drop", "drop_and_send", "hold_and_send", "drop_until_toggle",
		  "hold_until_deactivation", "packet_group_send"}},
		{"retransmission_mode", {"none", "only_seq", "only_ack", "both"}},
		{"subsequent_packet_hold_mode", {"none", "seq_only", "ack_only", "seq_ack"}},
		{"group_order", {"fifo", "lifo", "random"}},
		{"ratio_selection", {"first", "last", "random"}},
		{"client_address_enforcement", {"none", "source", "destination", "both"}},
		{"server_direction", {"source", "destination", "both"}},
	};
	for (const auto& row : table)
		if (entry.key == row.key)
			return row.values;
	return {};
}

std::vector<std::string> list_item_template(const std::string& list_key)
{
	if (list_key != "profiles")
		return {};
	return {"- name: \"New profile\"",
			"  key: x",
			"  mode: toggle",
			"  delay_mode: from_timestamp",
			"  delay_ms: 100",
			"  retransmission_mode: none",
			"  capture_options:",
			"    outbound: true",
			"    inbound: true"};
}

std::string yaml_scalar(const std::string& text)
{
	if (text.empty())
		return "\"\"";
	const char first = text.front();
	if (first == '"' || first == '\'' || first == '[' || first == '{')
		return text;
	if (text.find_first_of(":#") == std::string::npos && text.front() != ' ' && text.back() != ' ')
		return text;
	std::string quoted = "\"";
	for (const char c : text)
	{
		if (c == '"' || c == '\\')
			quoted += '\\';
		quoted += c;
	}
	return quoted + "\"";
}

const char* new_profile_template()
{
	return "# New lagsw profile file. Hold a profile's key to activate it; every setting is described in README.md.\n"
		   "default_view: log\n"
		   "\n"
		   "servers:\n"
		   "  addresses:\n"
		   "    - \"127.0.0.1:example\"\n"
		   "\n"
		   "profiles:\n"
		   "  - name: \"Delay\"\n"
		   "    key: x\n"
		   "    mode: toggle\n"
		   "    delay_mode: from_timestamp\n"
		   "    delay_ms: 100\n"
		   "    retransmission_mode: none\n"
		   "    capture_options:\n"
		   "      outbound: true\n"
		   "      inbound: true\n";
}

}  // namespace config_tui

#endif
