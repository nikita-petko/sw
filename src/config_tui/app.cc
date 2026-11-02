#include "config_tui.h"

#ifdef LAGSW_FEATURE_CONFIG_TUI

#	include <algorithm>
#	include <cstdio>
#	include <filesystem>
#	include <fstream>
#	include <iterator>
#	include <sstream>
#	include <system_error>

#	include "platform.h"

namespace config_tui {
namespace {
	namespace fs  = std::filesystem;
	namespace key = platform::edit_key;

	constexpr const char* kReset   = "\033[0m";
	constexpr const char* kReverse = "\033[7m";
	constexpr const char* kDim	   = "\033[2m";
	constexpr const char* kBold	   = "\033[1m";
	constexpr const char* kRed	   = "\033[1;31m";
	constexpr const char* kGreen   = "\033[32m";

	/// Cuts the text to `width` columns (without splitting a UTF-8 sequence) and pads it with spaces.
	std::string fit(const std::string& text, size_t width)
	{
		std::string out;
		size_t		columns = 0;
		for (const char c : text)
		{
			const unsigned char byte = static_cast<unsigned char>(c);
			if ((byte & 0xC0) == 0x80)
			{
				out += c;
				continue;
			}
			if (columns >= width)
				break;
			out += byte < 0x20 ? ' ' : c;
			++columns;
		}
		out.append(width - columns, ' ');
		return out;
	}

	/// The last file line of an outline entry and everything nested under it.
	size_t subtree_end(const std::vector<OutlineEntry>& outline, size_t index)
	{
		size_t end = outline[index].line;
		for (size_t i = index + 1; i < outline.size() && outline[i].depth > outline[index].depth; ++i)
			end = (std::max)(end, outline[i].line);
		return end;
	}

	/// What a menu row calls an entry: a section's name, a list entry's name or value, or a setting's key.
	std::string item_label(const std::vector<OutlineEntry>& outline, size_t index)
	{
		const OutlineEntry& entry = outline[index];
		if (entry.leaf)
			return entry.path.back() == ']' ? entry.value : entry.key;
		std::string name = entry.key;
		if (!name.empty() && name.front() == '[')
			for (size_t i = index + 1; i < outline.size() && outline[i].depth > entry.depth; ++i)
				if (outline[i].leaf && outline[i].depth == entry.depth + 1 && outline[i].key == "name")
				{
					name += " " + outline[i].value;
					break;
				}
		return name;
	}

	std::vector<std::string> split_lines(const std::string& content)
	{
		std::vector<std::string> lines;
		std::string				 line;
		for (const char c : content)
		{
			if (c == '\n')
			{
				lines.push_back(line);
				line.clear();
			}
			else if (c != '\r')
				line += c;
		}
		if (!line.empty())
			lines.push_back(line);
		return lines;
	}

	bool exists(const std::string& path)
	{
		std::error_code error;
		return fs::exists(path, error);
	}

	std::string trimmed(const std::string& text)
	{
		const size_t begin = text.find_first_not_of(" \t");
		return begin == std::string::npos ? std::string() : text.substr(begin, text.find_last_not_of(" \t") - begin + 1);
	}

	bool printable(int code)
	{
		return (code >= 0x20 && code < 0x7F) || (code >= 0x80 && code <= 0xFF);
	}

	void pop_character(std::string& text)
	{
		while (!text.empty() && (static_cast<unsigned char>(text.back()) & 0xC0) == 0x80)
			text.pop_back();
		if (!text.empty())
			text.pop_back();
	}

	/// The 1-based line number a loader complaint names ("... at line 12 ..."), or 0.
	size_t complaint_line(const std::string& complaint)
	{
		const size_t found = complaint.find("line ");
		if (found == std::string::npos)
			return 0;
		size_t number = 0;
		for (size_t i = found + 5; i < complaint.size() && complaint[i] >= '0' && complaint[i] <= '9'; ++i)
			number = number * 10 + static_cast<size_t>(complaint[i] - '0');
		return number;
	}
}  // namespace

App::App(Services services, std::optional<std::string> current_file) : services_(std::move(services)), swapped_in_(current_file.has_value())
{
	recent_ = load_recent(services_.recent_file);
	refresh_statuses();
	if (current_file)
		open_file(absolute_path(*current_file));
}

void App::refresh_statuses()
{
	statuses_.clear();
	for (const RecentEntry& entry : recent_)
		statuses_.push_back(probe_file(entry.path, services_.validate));
}

void App::remember(const std::string& path)
{
	add_recent(recent_, path, services_.now());
	if (!services_.recent_file.empty())
		save_recent(services_.recent_file, recent_);
	statuses_.clear();
}

void App::begin_prompt(Prompt::Kind kind, const std::string& label, const std::string& text)
{
	prompt_ = {kind, label, text, {}, 0};
}

std::string App::text() const
{
	const char* eol = crlf_ ? "\r\n" : "\n";
	std::string result;
	for (const std::string& line : lines_)
		result += line + eol;
	return result;
}

void App::pin_error(const std::string& error)
{
	message_		  = error;
	message_is_error_ = true;
	tab_			  = Tab::raw;
	const size_t line = complaint_line(error);
	if (line > 0 && line <= lines_.size())
	{
		cursor_row_	   = line - 1;
		cursor_column_ = 0;
	}
}

bool App::open_file(const std::string& requested)
{
	// `requested` may refer into recent_, which remember() reorders
	const std::string path = requested;
	std::ifstream	  input(path, std::ios::binary);
	if (!input)
	{
		message_		  = (exists(path) ? "Cannot read " : "Not found: ") + path;
		message_is_error_ = true;
		return false;
	}
	const std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
	lines_	   = split_lines(content);
	crlf_	   = content.find("\r\n") != std::string::npos;
	file_path_ = path;
	dirty_	   = false;
	backed_up_ = false;
	screen_	   = Screen::editor;
	tab_	   = Tab::form;
	menu_reset();
	cursor_row_	   = 0;
	cursor_column_ = 0;
	raw_scroll_	   = 0;
	remember(path);
	const std::string complaint = services_.validate ? services_.validate(path) : std::string();
	if (!complaint.empty())
		pin_error(complaint);
	return true;
}

void App::start_new(const std::string& path)
{
	const std::string absolute = absolute_path(path);
	if (exists(absolute))
	{
		message_		  = absolute + " already exists; open it instead";
		message_is_error_ = true;
		return;
	}
	lines_	   = split_lines(new_profile_template());
	crlf_	   = false;
	file_path_ = absolute;
	dirty_	   = true;
	backed_up_ = false;
	screen_	   = Screen::editor;
	tab_	   = Tab::form;
	menu_reset();
	cursor_row_		  = 0;
	cursor_column_	  = 0;
	raw_scroll_		  = 0;
	message_		  = "New file, not saved yet";
	message_is_error_ = false;
}

bool App::save(bool force)
{
	std::error_code error;
	fs::create_directories(fs::path(file_path_).parent_path(), error);
	const std::string temporary = file_path_ + ".lagsw-tmp";
	{
		std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
		output << text();
		if (!output.good())
		{
			message_		  = "Cannot write " + temporary;
			message_is_error_ = true;
			return false;
		}
	}
	std::string complaint = services_.validate ? services_.validate(temporary) : std::string();
	for (size_t at = complaint.find(temporary); at != std::string::npos; at = complaint.find(temporary, at + file_path_.size()))
		complaint.replace(at, temporary.size(), file_path_);
	if (!complaint.empty() && !force)
	{
		fs::remove(temporary, error);
		begin_prompt(Prompt::Kind::confirm_save_invalid, complaint + "  Save anyway? (y/n)");
		return false;
	}
	if (!backed_up_ && exists(file_path_))
	{
		fs::copy_file(file_path_, file_path_ + ".bak", fs::copy_options::overwrite_existing, error);
		backed_up_ = true;
	}
	fs::rename(temporary, file_path_, error);
	if (error)
	{
		fs::remove(temporary, error);
		message_		  = "Cannot replace " + file_path_ + ": " + error.message();
		message_is_error_ = true;
		return false;
	}
	dirty_ = false;
	remember(file_path_);
	if (complaint.empty())
	{
		message_		  = "Saved " + file_path_;
		message_is_error_ = false;
	}
	else
	{
		message_		  = "Saved with errors: " + complaint;
		message_is_error_ = true;
	}
	return true;
}

bool App::save_and_run()
{
	if (dirty_ || !exists(file_path_))
	{
		if (!save(false))
			return false;
	}
	else
	{
		const std::string complaint = services_.validate ? services_.validate(file_path_) : std::string();
		if (!complaint.empty())
		{
			pin_error(complaint);
			return false;
		}
	}
	chosen_path_ = file_path_;
	outcome_	 = Outcome::run;
	return true;
}

void App::leave_editor()
{
	if (dirty_)
	{
		begin_prompt(Prompt::Kind::confirm_discard, "Discard the unsaved changes? (y/n)");
		return;
	}
	screen_ = Screen::loader;
	refresh_statuses();
	selected_ = 0;
}

void App::forget_selected()
{
	if (selected_ >= recent_.size())
		return;
	recent_.erase(recent_.begin() + static_cast<std::ptrdiff_t>(selected_));
	if (!services_.recent_file.empty())
		save_recent(services_.recent_file, recent_);
	refresh_statuses();
	selected_		  = (std::min)(selected_, selectable_count() - 1);
	message_		  = "Removed from the list; the file itself was not touched";
	message_is_error_ = false;
}

void App::activate_selected()
{
	if (selected_ == recent_.size())
	{
		begin_prompt(Prompt::Kind::new_path, "New profile file", "profiles/new.sw.yml");
		return;
	}
	if (selected_ == recent_.size() + 1)
	{
		begin_prompt(Prompt::Kind::open_path, "Open file");
		return;
	}
	if (statuses_.size() != recent_.size())
		refresh_statuses();
	if (statuses_[selected_].state == FileState::missing)
	{
		begin_prompt(Prompt::Kind::confirm_missing,
					 recent_[selected_].path + " is gone. [r] re-create from the template  [d] remove from the list  Esc cancel");
		return;
	}
	open_file(recent_[selected_].path);
}

void App::run_selected()
{
	if (selected_ >= recent_.size())
		return;
	const std::string path	 = recent_[selected_].path;
	const FileStatus  status = probe_file(path, services_.validate);
	if (status.state != FileState::ok)
	{
		message_		  = path + (status.state == FileState::missing ? ": not found" : ": cannot read: " + status.message);
		message_is_error_ = true;
		return;
	}
	remember(path);
	chosen_path_ = path;
	outcome_	 = Outcome::run;
}

void App::handle_key(int code)
{
	if (code == key::none || outcome_ != Outcome::running)
		return;
	if (code == key::terminate)
	{
		outcome_ = Outcome::quit;
		return;
	}
	message_.clear();
	message_is_error_ = false;
	if (prompt_.kind != Prompt::Kind::none)
		key_prompt(code);
	else if (screen_ == Screen::loader)
		key_loader(code);
	else
		key_editor(code);
	change();
}

void App::key_loader(int code)
{
	switch (code)
	{
		case key::up:
			selected_ = selected_ > 0 ? selected_ - 1 : 0;
			break;
		case key::down:
			selected_ = (std::min)(selected_ + 1, selectable_count() - 1);
			break;
		case key::home:
			selected_ = 0;
			break;
		case key::end:
			selected_ = selectable_count() - 1;
			break;
		case key::enter:
			activate_selected();
			break;
		case key::del:
		case 'd':
			forget_selected();
			break;
		case key::escape:
			outcome_ = swapped_in_ ? Outcome::cancel : Outcome::quit;
			break;
		case 'q':
		case 'Q':
			outcome_ = Outcome::quit;
			break;
		case 'n':
			begin_prompt(Prompt::Kind::new_path, "New profile file", "profiles/new.sw.yml");
			break;
		case 'o':
			begin_prompt(Prompt::Kind::open_path, "Open file");
			break;
		case 'r':
			refresh_statuses();
			message_ = "Checked every file again";
			break;
		default:
			if (code == key::ctrl('R'))
				run_selected();
	}
}

void App::key_editor(int code)
{
	if (code == key::ctrl('S'))
		save(false);
	else if (code == key::ctrl('R'))
		save_and_run();
	else if (code == key::ctrl('T') || (code == key::tab && tab_ == Tab::form))
		tab_ = tab_ == Tab::form ? Tab::raw : Tab::form;
	else if (code == key::escape && tab_ == Tab::form && !menu_path_.empty())
		menu_up();
	else if (code == key::escape)
		leave_editor();
	else if (tab_ == Tab::form)
		key_form(code);
	else
		key_raw(code);
}

void App::menu_reset()
{
	menu_path_.clear();
	menu_trail_.clear();
	menu_selected_ = 0;
	form_scroll_   = 0;
}

void App::menu_up()
{
	if (menu_path_.empty())
		return;
	const std::vector<OutlineEntry> outline = build_outline(lines_);
	const auto found = std::find_if(outline.begin(), outline.end(), [&](const OutlineEntry& e) { return !e.leaf && e.path == menu_path_; });
	std::string parent;
	if (found != outline.end())
	{
		// the parent is the nearest earlier header one level up
		for (auto it = found; it != outline.begin();)
		{
			--it;
			if (!it->leaf && it->depth == found->depth - 1)
			{
				parent = it->path;
				break;
			}
		}
	}
	menu_path_	   = parent;
	menu_selected_ = menu_trail_.empty() ? 0 : menu_trail_.back();
	if (!menu_trail_.empty())
		menu_trail_.pop_back();
	form_scroll_ = 0;
}

std::vector<size_t> App::menu_items(const std::vector<OutlineEntry>& outline)
{
	std::vector<size_t> items;
	int					depth = 0;
	size_t				first = 0;
	if (!menu_path_.empty())
	{
		const auto found =
			std::find_if(outline.begin(), outline.end(), [&](const OutlineEntry& e) { return !e.leaf && e.path == menu_path_; });
		if (found == outline.end())
		{
			menu_reset();
			return menu_items(outline);
		}
		first = static_cast<size_t>(found - outline.begin()) + 1;
		depth = found->depth + 1;
	}
	for (size_t i = first; i < outline.size() && outline[i].depth >= depth; ++i)
		if (outline[i].depth == depth)
			items.push_back(i);
	return items;
}

bool App::is_list_menu(const std::vector<OutlineEntry>& outline, const std::vector<size_t>& items) const
{
	if (menu_path_.empty())
		return false;
	return items.empty() || outline[items.front()].path.back() == ']';
}

void App::start_add(const std::vector<OutlineEntry>& outline, const std::vector<size_t>& items)
{
	const auto header =
		std::find_if(outline.begin(), outline.end(), [&](const OutlineEntry& e) { return !e.leaf && e.path == menu_path_; });
	const bool scalar = items.empty() ? header == outline.end() || list_item_template(header->key).empty() : outline[items.front()].leaf;
	if (scalar)
	{
		edit_path_ = menu_path_;
		begin_prompt(Prompt::Kind::add_value, "Add to " + menu_path_, "");
	}
	else
		add_item({});
}

void App::add_item(const std::string& scalar)
{
	const std::vector<OutlineEntry> outline = build_outline(lines_);
	const auto						header =
		std::find_if(outline.begin(), outline.end(), [&](const OutlineEntry& e) { return !e.leaf && e.path == menu_path_; });
	if (header == outline.end())
		return;
	const std::vector<size_t> items	 = menu_items(outline);
	size_t					  at	 = header->line + 1;
	size_t					  indent = lines_[header->line].find_first_not_of(' ') + 2;
	if (!items.empty())
	{
		at	   = subtree_end(outline, items.back()) + 1;
		indent = lines_[outline[items.front()].line].find_first_not_of(' ');
	}
	std::vector<std::string> added;
	if (!scalar.empty())
		added.push_back("- " + yaml_scalar(scalar));
	else
	{
		added = list_item_template(header->key);
		if (added.empty() && !items.empty())
		{
			// no template: copy the last entry so the new one starts from a complete example
			const size_t first = outline[items.back()].line;
			const size_t base  = lines_[first].find_first_not_of(' ');
			for (size_t line = first; line < at; ++line)
				added.push_back(lines_[line].size() >= base ? lines_[line].substr(base) : lines_[line]);
		}
	}
	if (added.empty())
		return;
	for (std::string& line : added)
		if (!line.empty())
			line.insert(0, indent, ' ');
	lines_.insert(lines_.begin() + static_cast<std::ptrdiff_t>(at), added.begin(), added.end());
	menu_selected_ = items.size();
	touch();
	message_		  = scalar.empty() ? "Entry added; edit its settings below" : "Entry added";
	message_is_error_ = false;
}

void App::remove_item()
{
	const std::vector<OutlineEntry> outline = build_outline(lines_);
	const auto found = std::find_if(outline.begin(), outline.end(), [&](const OutlineEntry& e) { return e.path == edit_path_; });
	if (found == outline.end())
		return;
	const size_t first = found->line;
	const size_t last  = subtree_end(outline, static_cast<size_t>(found - outline.begin()));
	lines_.erase(lines_.begin() + static_cast<std::ptrdiff_t>(first), lines_.begin() + static_cast<std::ptrdiff_t>(last) + 1);
	touch();
	message_		  = "Entry removed";
	message_is_error_ = false;
}

void App::key_form(int code)
{
	const std::vector<OutlineEntry> outline = build_outline(lines_);
	const std::vector<size_t>		items	= menu_items(outline);
	const bool						list	= is_list_menu(outline, items);
	const size_t					rows	= items.size() + (list ? 1 : 0);
	if (rows == 0)
	{
		if (code == key::left || code == key::backspace)
			menu_up();
		return;
	}
	menu_selected_		= (std::min)(menu_selected_, rows - 1);
	const bool	 on_add = list && menu_selected_ == items.size();
	const size_t page	= static_cast<size_t>(page_rows_);
	switch (code)
	{
		case key::up:
			menu_selected_ = menu_selected_ > 0 ? menu_selected_ - 1 : 0;
			return;
		case key::down:
			menu_selected_ = (std::min)(menu_selected_ + 1, rows - 1);
			return;
		case key::page_up:
			menu_selected_ = menu_selected_ > page ? menu_selected_ - page : 0;
			return;
		case key::page_down:
			menu_selected_ = (std::min)(menu_selected_ + page, rows - 1);
			return;
		case key::home:
			menu_selected_ = 0;
			return;
		case key::end:
			menu_selected_ = rows - 1;
			return;
		case key::left:
		case key::backspace:
			menu_up();
			return;
		case 'a':
		case '+':
			if (list)
				start_add(outline, items);
			return;
		default:
			break;
	}
	if (on_add)
	{
		if (code == key::enter || code == key::right || code == ' ')
			start_add(outline, items);
		return;
	}
	const OutlineEntry& entry = outline[items[menu_selected_]];
	if (list && (code == key::del || code == 'd'))
	{
		edit_path_ = entry.path;
		begin_prompt(Prompt::Kind::confirm_remove, "Remove " + item_label(outline, items[menu_selected_]) + "? (y/n)");
		return;
	}
	if (code == key::right || code == key::enter)
	{
		if (!entry.leaf)
		{
			menu_trail_.push_back(menu_selected_);
			menu_path_	   = entry.path;
			menu_selected_ = 0;
			form_scroll_   = 0;
			return;
		}
		const std::vector<std::string> options = value_choices(entry);
		const bool					   toggle  = options.size() == 2 && options[0] == "true";
		if (toggle)
		{
			if (code == key::enter)
				toggle_checkbox(entry);
			return;
		}
		edit_path_ = entry.path;
		if (options.empty())
		{
			begin_prompt(Prompt::Kind::edit_value, entry.path, entry.value);
			return;
		}
		// fixed values are picked from a drop-down; a value outside the list is kept as an extra choice
		std::string current = entry.value;
		if (current.size() >= 2 && (current.front() == '"' || current.front() == '\'') && current.back() == current.front())
			current = current.substr(1, current.size() - 2);
		begin_prompt(Prompt::Kind::select_value, entry.path);
		prompt_.options = options;
		auto found		= std::find(prompt_.options.begin(), prompt_.options.end(), current);
		if (found == prompt_.options.end())
		{
			prompt_.options.insert(prompt_.options.begin(), current);
			found = prompt_.options.begin();
		}
		prompt_.choice = static_cast<size_t>(found - prompt_.options.begin());
		return;
	}
	if (code == ' ' && entry.leaf)
	{
		const std::vector<std::string> options = value_choices(entry);
		if (options.size() == 2 && options[0] == "true")
			toggle_checkbox(entry);
	}
}

void App::toggle_checkbox(const OutlineEntry& entry)
{
	std::string current = entry.value;
	if (current.size() >= 2 && (current.front() == '"' || current.front() == '\'') && current.back() == current.front())
		current = current.substr(1, current.size() - 2);
	lines_[entry.line] = replace_value(lines_[entry.line], entry, current == "true" ? "false" : "true");
	touch();
}

void App::key_raw(int code)
{
	if (lines_.empty())
		lines_.emplace_back();
	cursor_row_		  = (std::min)(cursor_row_, lines_.size() - 1);
	std::string& line = lines_[cursor_row_];
	cursor_column_	  = (std::min)(cursor_column_, line.size());
	switch (code)
	{
		case key::left:
			if (cursor_column_ > 0)
				--cursor_column_;
			else if (cursor_row_ > 0)
			{
				--cursor_row_;
				cursor_column_ = lines_[cursor_row_].size();
			}
			return;
		case key::right:
			if (cursor_column_ < line.size())
				++cursor_column_;
			else if (cursor_row_ + 1 < lines_.size())
			{
				++cursor_row_;
				cursor_column_ = 0;
			}
			return;
		case key::up:
			cursor_row_ = cursor_row_ > 0 ? cursor_row_ - 1 : 0;
			return;
		case key::down:
			cursor_row_ = (std::min)(cursor_row_ + 1, lines_.size() - 1);
			return;
		case key::page_up:
			cursor_row_ = cursor_row_ > static_cast<size_t>(page_rows_) ? cursor_row_ - static_cast<size_t>(page_rows_) : 0;
			return;
		case key::page_down:
			cursor_row_ = (std::min)(cursor_row_ + static_cast<size_t>(page_rows_), lines_.size() - 1);
			return;
		case key::home:
			cursor_column_ = 0;
			return;
		case key::end:
			cursor_column_ = line.size();
			return;
		case key::enter:
			{
				const size_t indent =
					(std::min)(line.find_first_not_of(' ') == std::string::npos ? line.size() : line.find_first_not_of(' '),
							   cursor_column_);
				const std::string rest = line.substr(cursor_column_);
				line.erase(cursor_column_);
				lines_.insert(lines_.begin() + static_cast<std::ptrdiff_t>(cursor_row_) + 1, std::string(indent, ' ') + rest);
				++cursor_row_;
				cursor_column_ = indent;
				touch();
				return;
			}
		case key::backspace:
			if (cursor_column_ > 0)
			{
				line.erase(--cursor_column_, 1);
				touch();
			}
			else if (cursor_row_ > 0)
			{
				const std::string current = line;
				--cursor_row_;
				cursor_column_ = lines_[cursor_row_].size();
				lines_[cursor_row_] += current;
				lines_.erase(lines_.begin() + static_cast<std::ptrdiff_t>(cursor_row_) + 1);
				touch();
			}
			return;
		case key::del:
			if (cursor_column_ < line.size())
			{
				line.erase(cursor_column_, 1);
				touch();
			}
			else if (cursor_row_ + 1 < lines_.size())
			{
				line += lines_[cursor_row_ + 1];
				lines_.erase(lines_.begin() + static_cast<std::ptrdiff_t>(cursor_row_) + 1);
				touch();
			}
			return;
		case key::tab:
			line.insert(cursor_column_, "  ");
			cursor_column_ += 2;
			touch();
			return;
	}
	if (printable(code))
	{
		line.insert(cursor_column_++, 1, static_cast<char>(code));
		touch();
	}
}

void App::key_prompt(int code)
{
	switch (prompt_.kind)
	{
		case Prompt::Kind::confirm_discard:
			if (code == 'y' || code == 'Y')
			{
				prompt_.kind = Prompt::Kind::none;
				dirty_		 = false;
				leave_editor();
			}
			else if (code == 'n' || code == 'N' || code == key::escape)
				prompt_.kind = Prompt::Kind::none;
			return;
		case Prompt::Kind::confirm_save_invalid:
			if (code == 'y' || code == 'Y')
			{
				prompt_.kind = Prompt::Kind::none;
				save(true);
			}
			else if (code == 'n' || code == 'N' || code == key::escape)
				prompt_.kind = Prompt::Kind::none;
			return;
		case Prompt::Kind::select_value:
			{
				const size_t count = prompt_.options.size();
				if (code == key::up)
					prompt_.choice = prompt_.choice > 0 ? prompt_.choice - 1 : 0;
				else if (code == key::down)
					prompt_.choice = (std::min)(prompt_.choice + 1, count - 1);
				else if (code == key::home)
					prompt_.choice = 0;
				else if (code == key::end)
					prompt_.choice = count - 1;
				else if (code == key::escape)
					prompt_.kind = Prompt::Kind::none;
				else if (code == key::enter)
				{
					const std::string value					= prompt_.options[prompt_.choice];
					prompt_.kind							= Prompt::Kind::none;
					const std::vector<OutlineEntry> outline = build_outline(lines_);
					const auto						found =
						std::find_if(outline.begin(), outline.end(), [&](const OutlineEntry& e) { return e.leaf && e.path == edit_path_; });
					if (found != outline.end() &&
						lines_[found->line].substr(found->value_begin, found->value_end - found->value_begin) != value)
					{
						lines_[found->line] = replace_value(lines_[found->line], *found, value);
						touch();
					}
				}
				return;
			}
		case Prompt::Kind::confirm_remove:
			prompt_.kind = Prompt::Kind::none;
			if (code == 'y' || code == 'Y')
				remove_item();
			return;
		case Prompt::Kind::confirm_missing:
			if (code == 'r' || code == 'R')
			{
				prompt_.kind = Prompt::Kind::none;
				start_new(selected_ < recent_.size() ? recent_[selected_].path : std::string());
			}
			else if (code == 'd' || code == 'D')
			{
				prompt_.kind = Prompt::Kind::none;
				forget_selected();
			}
			else if (code == key::escape)
				prompt_.kind = Prompt::Kind::none;
			return;
		default:
			break;
	}
	if (code == key::escape)
	{
		prompt_.kind = Prompt::Kind::none;
		return;
	}
	if (code == key::enter)
	{
		const Prompt prompt		= prompt_;
		prompt_.kind			= Prompt::Kind::none;
		const std::string value = prompt.kind == Prompt::Kind::edit_value ? prompt.text : trimmed(prompt.text);
		if (prompt.kind == Prompt::Kind::add_value)
		{
			if (!value.empty())
				add_item(value);
			return;
		}
		if (prompt.kind == Prompt::Kind::edit_value)
		{
			const std::vector<OutlineEntry> outline = build_outline(lines_);
			const auto						found =
				std::find_if(outline.begin(), outline.end(), [&](const OutlineEntry& e) { return e.leaf && e.path == edit_path_; });
			if (found != outline.end())
			{
				const OutlineEntry& entry = *found;
				if (lines_[entry.line].substr(entry.value_begin, entry.value_end - entry.value_begin) != value)
				{
					lines_[entry.line] = replace_value(lines_[entry.line], entry, value);
					touch();
				}
			}
		}
		else if (value.empty())
			return;
		else if (prompt.kind == Prompt::Kind::open_path)
			open_file(absolute_path(value));
		else if (prompt.kind == Prompt::Kind::new_path)
			start_new(value);
		return;
	}
	if (code == key::backspace)
		pop_character(prompt_.text);
	else if (code == key::ctrl('U'))
		prompt_.text.clear();
	else if (printable(code))
		prompt_.text += static_cast<char>(code);
}

std::string App::render(int width, int height)
{
	const size_t columns = static_cast<size_t>((std::max)(width, 20));
	const size_t total	 = static_cast<size_t>((std::max)(height, 6));
	const size_t body	 = total - 4;
	page_rows_			 = static_cast<int>(body);
	std::vector<std::string> rows(total, std::string(columns, ' '));
	std::string				 overlay;

	const auto styled = [&](const char* style, const std::string& text) { return std::string(style) + fit(text, columns) + kReset; };

	if (screen_ == Screen::loader)
	{
		rows[0] = styled(kReverse, " lagsw - profile loader");
		rows[1] = styled(kDim, " Recent profile files, newest first");
		if (statuses_.size() != recent_.size())
			refresh_statuses();
		const size_t count = selectable_count();
		if (selected_ < list_scroll_)
			list_scroll_ = selected_;
		if (selected_ >= list_scroll_ + body)
			list_scroll_ = selected_ + 1 - body;
		for (size_t row = 0; row < body && list_scroll_ + row < count; ++row)
		{
			const size_t index	 = list_scroll_ + row;
			const bool	 current = index == selected_;
			const char*	 base	 = current ? kReverse : "";
			std::string	 line;
			if (index < recent_.size())
			{
				const FileStatus& status	  = statuses_[index];
				const bool		  problem	  = status.state != FileState::ok;
				std::string		  label		  = status.state == FileState::missing ? "not found" : "cannot read: " + status.message;
				std::string		  plain		  = fit(recent_[index].path + (problem ? "  " + label : std::string()), columns - 3);
				const size_t	  path_length = (std::min)(recent_[index].path.size(), plain.size());
				line						  = std::string(base) + " " + (problem ? std::string(kRed) + "!" + kReset + base : " ") + " " +
												plain.substr(0, path_length);
				if (problem)
					line += std::string(kRed) + plain.substr(path_length) + kReset;
				else
					line += plain.substr(path_length);
			}
			else
				line = std::string(base) + fit(index == recent_.size() ? "   + New profile..." : "   + Open path...", columns);
			rows[2 + row] = line + kReset;
		}
		if (recent_.empty() && body > 0)
			rows[2] = std::string(kDim) + fit("   (nothing opened yet)", columns) + kReset;
		rows[total - 1] = styled(kDim, " Up/Down select  Enter edit  Ctrl+R run  n new  o open  d forget  r check again  q quit");
	}
	else
	{
		std::string title = " lagsw - " + file_path_ + (dirty_ ? " *" : "");
		rows[0]			  = styled(kReverse, title + "   [" + (tab_ == Tab::form ? "Form" : "Raw") + "]");
		if (tab_ == Tab::form)
		{
			const std::vector<OutlineEntry> outline = build_outline(lines_);
			const std::vector<size_t>		items	= menu_items(outline);
			const bool						list	= is_list_menu(outline, items);
			const size_t					count	= items.size() + (list ? 1 : 0);
			// rows 1 .. total-3 hold a bordered box, centred, as tall as its content needs
			const size_t inner_max	= total - 5;
			const size_t inner		= (std::min)((std::max)(count, size_t{3}), inner_max);
			const size_t box_width	= (std::min)(columns - 2, size_t{76});
			const size_t text_width = box_width - 4;
			const size_t left		= (columns - box_width) / 2 + 1;
			const size_t top		= 2 + (inner_max - inner) / 2;
			page_rows_				= static_cast<int>(inner);
			menu_selected_			= count == 0 ? 0 : (std::min)(menu_selected_, count - 1);
			if (menu_selected_ < form_scroll_)
				form_scroll_ = menu_selected_;
			if (menu_selected_ >= form_scroll_ + inner)
				form_scroll_ = menu_selected_ + 1 - inner;

			std::string crumbs = "Settings";
			for (const char c : menu_path_)
				crumbs += c == '.' ? std::string(" > ") : std::string(1, c);
			const auto border = [&](const char* open, const char* close, const std::string& title) {
				const std::string shown = title.empty() ? std::string() : " " + fit(title, (std::min)(title.size(), text_width - 2)) + " ";
				size_t			  used	= 0;
				for (const char c : shown)
					if ((static_cast<unsigned char>(c) & 0xC0) != 0x80)
						++used;
				std::string line = open;
				line += "\u2500" + shown;
				for (size_t i = used + 1; i < box_width - 2; ++i)
					line += "\u2500";
				return line + close;
			};
			const auto place = [&](size_t row, const std::string& content) {
				overlay += "\033[" + std::to_string(row) + ";" + std::to_string(left) + "H" + content + kReset;
			};
			place(top, border("\u250c", "\u2510", crumbs));
			const size_t label_width = (std::min)(text_width / 2, size_t{30});
			for (size_t row = 0; row < inner; ++row)
			{
				const size_t index = form_scroll_ + row;
				std::string	 text;
				const char*	 style = "";
				if (index < items.size())
				{
					const OutlineEntry& entry = outline[items[index]];
					const std::string	label = item_label(outline, items[index]);
					if (!entry.leaf)
					{
						text = fit(label, text_width - 2) + " >";
					}
					else
					{
						const std::vector<std::string> options = value_choices(entry);
						if (options.size() == 2 && options[0] == "true")
						{
							std::string value = entry.value;
							if (value.size() >= 2 && (value.front() == '"' || value.front() == '\''))
								value = value.substr(1, value.size() - 2);
							text = std::string("[") + (value == "true" ? "x" : " ") + "] " + entry.key;
						}
						else if (entry.path.back() == ']')
							text = entry.value;
						else
						{
							const std::string name = fit(entry.key, label_width);
							text				   = name + "  " + entry.value;
						}
					}
				}
				else if (index == items.size() && list)
				{
					text  = "+ Add item";
					style = kGreen;
				}
				else if (count == 0 && row == 0)
				{
					text  = "(empty)";
					style = kDim;
				}
				const bool current = index == menu_selected_ && index < count;
				place(top + 1 + row,
					  std::string(kReset) + "\u2502 " + (current ? kReverse : style) + fit(text, text_width) + kReset + " \u2502");
			}
			std::string position;
			if (count > inner)
				position = std::to_string(menu_selected_ + 1) + "/" + std::to_string(count);
			place(top + 1 + inner, border("\u2514", "\u2518", position));
			rows[1]			= styled(kDim, " Settings of the file; comments and untouched lines are kept as they are");
			rows[total - 1] = styled(kDim,
									 list ? " Up/Down select  Enter edit  a add  Del remove  Left/Esc back  Ctrl+S save  Tab raw"
										  : " Up/Down select  Enter open/edit/pick  Space toggle  Left/Esc back  Ctrl+S save  Tab raw");
		}
		else
		{
			cursor_row_ = (std::min)(cursor_row_, lines_.empty() ? 0 : lines_.size() - 1);
			if (cursor_row_ < raw_scroll_)
				raw_scroll_ = cursor_row_;
			if (cursor_row_ >= raw_scroll_ + body + 0)
				raw_scroll_ = cursor_row_ + 1 - body;
			rows[1]					= styled(kDim, " Raw YAML");
			const size_t text_width = columns > 6 ? columns - 6 : 1;
			for (size_t row = 0; row < body && raw_scroll_ + row < (std::max)(lines_.size(), size_t{1}); ++row)
			{
				const size_t	  index = raw_scroll_ + row;
				const std::string line	= index < lines_.size() ? lines_[index] : std::string();
				char			  number[16];
				std::snprintf(number, sizeof(number), "%4zu ", index + 1);
				const size_t offset = index == cursor_row_ && cursor_column_ >= text_width ? cursor_column_ + 1 - text_width : 0;
				std::string	 shown	= offset < line.size() ? line.substr(offset) : std::string();
				std::string	 out	= std::string(kDim) + number + kReset;
				if (index == cursor_row_)
				{
					const size_t at		= cursor_column_ - offset;
					std::string	 before = fit(shown.substr(0, (std::min)(at, shown.size())), at);
					std::string	 under	= at < shown.size() ? shown.substr(at, 1) : " ";
					std::string	 after	= at + 1 < shown.size() ? shown.substr(at + 1) : std::string();
					out += before + kReverse + under + kReset + fit(after, text_width > at + 1 ? text_width - at - 1 : 0);
				}
				else
					out += fit(shown, text_width);
				rows[2 + row] = out + " ";
			}
			rows[total - 1] = styled(kDim, " Arrows move  Tab indents  Ctrl+S save  Ctrl+R save and run  Ctrl+T form  Esc back");
		}
	}

	if (prompt_.kind != Prompt::Kind::none)
	{
		const bool text_prompt = prompt_.kind == Prompt::Kind::open_path || prompt_.kind == Prompt::Kind::new_path;
		const bool dialog	   = prompt_.kind == Prompt::Kind::edit_value || prompt_.kind == Prompt::Kind::add_value ||
								 prompt_.kind == Prompt::Kind::select_value;
		if (!dialog)
			rows[total - 2] =
				text_prompt ? std::string(kBold) + fit(" " + prompt_.label + ": " + prompt_.text, columns - 1) + kReverse + " " + kReset
							: styled(kBold, " " + prompt_.label);
		if (text_prompt)
			rows[total - 1] = styled(kDim, " Enter confirm  Esc cancel");
	}
	else if (!message_.empty())
		rows[total - 2] = styled(message_is_error_ ? kRed : kGreen, " " + message_);

	std::string frame;
	for (size_t row = 0; row < rows.size(); ++row)
		frame += "\033[" + std::to_string(row + 1) + ";1H" + rows[row] + kReset;
	frame += overlay;
	const bool dialog =
		prompt_.kind == Prompt::Kind::edit_value || prompt_.kind == Prompt::Kind::add_value || prompt_.kind == Prompt::Kind::select_value;
	if (dialog && columns >= 12 && total >= 9)
	{
		const bool		  select = prompt_.kind == Prompt::Kind::select_value;
		const size_t	  width	 = (std::min)(columns - 4, size_t{64});
		const size_t	  inner	 = width - 4;
		const std::string title	 = select ? "Select value" : prompt_.kind == Prompt::Kind::add_value ? "Add item" : "Edit value";
		const auto		  line	 = [&](const std::string& content, const char* style) {
			return std::string(kBold) + "\u2502 " + kReset + style + fit(content, inner) + kReset + kBold + " \u2502" + kReset;
		};
		const auto edge = [&](const char* open, const char* close, const std::string& heading) {
			const std::string shown = heading.empty() ? std::string() : " " + heading + " ";
			std::string		  out	= std::string(kBold) + open + "\u2500" + shown;
			for (size_t i = shown.size() + 1; i < width - 2; ++i)
				out += "\u2500";
			return out + close + kReset;
		};
		std::vector<std::string> box;
		box.push_back(edge("\u250c", "\u2510", title));
		box.push_back(line(prompt_.label, kDim));
		if (select)
		{
			const size_t visible = (std::min)(prompt_.options.size(), (std::max)(total, size_t{9}) - 8);
			size_t		 first	 = prompt_.choice >= visible ? prompt_.choice + 1 - visible : 0;
			for (size_t i = 0; i < visible; ++i)
			{
				const size_t index = first + i;
				box.push_back(line(std::string(index == prompt_.choice ? "> " : "  ") + prompt_.options[index],
								   index == prompt_.choice ? kReverse : ""));
			}
			box.push_back(line("Up/Down choose  Enter select  Esc cancel", kDim));
		}
		else
		{
			// the tail of a long value stays visible next to the cursor
			const std::string value = prompt_.text.size() >= inner ? prompt_.text.substr(prompt_.text.size() - (inner - 1)) : prompt_.text;
			box.push_back(line(value + " ", kReverse));
			box.push_back(line("Enter confirm  Esc cancel", kDim));
		}
		box.push_back(edge("\u2514", "\u2518", ""));
		const size_t left = (columns - width) / 2 + 1;
		const size_t top  = (total > box.size() ? (total - box.size()) / 2 : 0) + 1;
		for (size_t i = 0; i < box.size(); ++i)
			frame += "\033[" + std::to_string(top + i) + ";" + std::to_string(left) + "H" + box[i];
	}
	return frame;
}

}  // namespace config_tui

#endif
