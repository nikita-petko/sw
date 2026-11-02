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
	namespace fs = std::filesystem;
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
	prompt_ = {kind, label, text};
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
	std::ifstream input(path, std::ios::binary);
	if (!input)
	{
		message_		  = (exists(path) ? "Cannot read " : "Not found: ") + path;
		message_is_error_ = true;
		return false;
	}
	const std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
	lines_		   = split_lines(content);
	crlf_		   = content.find("\r\n") != std::string::npos;
	file_path_	   = path;
	dirty_		   = false;
	backed_up_	   = false;
	screen_		   = Screen::editor;
	tab_		   = Tab::form;
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
	lines_		   = split_lines(new_profile_template());
	crlf_		   = false;
	file_path_	   = absolute;
	dirty_		   = true;
	backed_up_	   = false;
	screen_		   = Screen::editor;
	tab_		   = Tab::form;
	menu_reset();
	cursor_row_	   = 0;
	cursor_column_ = 0;
	raw_scroll_	   = 0;
	message_	   = "New file, not saved yet";
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
		begin_prompt(Prompt::Kind::confirm_missing, recent_[selected_].path + " is gone. [r] re-create from the template  [d] remove from the list  Esc cancel");
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
	const auto						found	= std::find_if(outline.begin(), outline.end(), [&](const OutlineEntry& e) { return !e.leaf && e.path == menu_path_; });
	std::string						parent;
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
		const auto found = std::find_if(outline.begin(), outline.end(), [&](const OutlineEntry& e) { return !e.leaf && e.path == menu_path_; });
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

void App::key_form(int code)
{
	const std::vector<OutlineEntry> outline = build_outline(lines_);
	const std::vector<size_t>		items	= menu_items(outline);
	if (items.empty())
	{
		if (code == key::left || code == key::backspace)
			menu_up();
		return;
	}
	menu_selected_			  = (std::min)(menu_selected_, items.size() - 1);
	const OutlineEntry& entry = outline[items[menu_selected_]];
	const size_t		page  = static_cast<size_t>(page_rows_);
	switch (code)
	{
		case key::up:
			menu_selected_ = menu_selected_ > 0 ? menu_selected_ - 1 : 0;
			return;
		case key::down:
			menu_selected_ = (std::min)(menu_selected_ + 1, items.size() - 1);
			return;
		case key::page_up:
			menu_selected_ = menu_selected_ > page ? menu_selected_ - page : 0;
			return;
		case key::page_down:
			menu_selected_ = (std::min)(menu_selected_ + page, items.size() - 1);
			return;
		case key::home:
			menu_selected_ = 0;
			return;
		case key::end:
			menu_selected_ = items.size() - 1;
			return;
		case key::left:
		case key::backspace:
			menu_up();
			return;
		case key::right:
		case key::enter:
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
			if (code == key::right || toggle)
			{
				if (toggle && code == key::enter)
					break;
				return;
			}
			edit_path_ = entry.path;
			begin_prompt(Prompt::Kind::edit_value, entry.path, entry.value);
			return;
		}
		default:
			break;
	}
	// Enter or Space toggles a checkbox; Space steps through the fixed values of other settings
	if (!entry.leaf || (code != ' ' && code != key::enter))
		return;
	const std::vector<std::string> choices = value_choices(entry);
	if (choices.empty())
		return;
	std::string current = entry.value;
	if (current.size() >= 2 && (current.front() == '"' || current.front() == '\'') && current.back() == current.front())
		current = current.substr(1, current.size() - 2);
	const auto   found = std::find(choices.begin(), choices.end(), current);
	const size_t index = found == choices.end() ? 0 : static_cast<size_t>(found - choices.begin());
	const size_t next  = found == choices.end() ? 0 : (index + 1) % choices.size();
	lines_[entry.line] = replace_value(lines_[entry.line], entry, choices[next]);
	touch();
}

void App::key_raw(int code)
{
	if (lines_.empty())
		lines_.emplace_back();
	cursor_row_		= (std::min)(cursor_row_, lines_.size() - 1);
	std::string& line = lines_[cursor_row_];
	cursor_column_	= (std::min)(cursor_column_, line.size());
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
			const size_t indent = (std::min)(line.find_first_not_of(' ') == std::string::npos ? line.size() : line.find_first_not_of(' '), cursor_column_);
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
		const Prompt prompt = prompt_;
		prompt_.kind		= Prompt::Kind::none;
		const std::string value = prompt.kind == Prompt::Kind::edit_value ? prompt.text : trimmed(prompt.text);
		if (prompt.kind == Prompt::Kind::edit_value)
		{
			const std::vector<OutlineEntry> outline = build_outline(lines_);
			const auto found = std::find_if(outline.begin(), outline.end(), [&](const OutlineEntry& e) { return e.leaf && e.path == edit_path_; });
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
			const size_t index	  = list_scroll_ + row;
			const bool	 current  = index == selected_;
			const char*	 base	  = current ? kReverse : "";
			std::string	 line;
			if (index < recent_.size())
			{
				const FileStatus& status  = statuses_[index];
				const bool		  problem = status.state != FileState::ok;
				std::string		  label	  = status.state == FileState::missing ? "not found" : "cannot read: " + status.message;
				std::string		  plain	  = fit(recent_[index].path + (problem ? "  " + label : std::string()), columns - 3);
				const size_t	  path_length = (std::min)(recent_[index].path.size(), plain.size());
				line = std::string(base) + " " + (problem ? std::string(kRed) + "!" + kReset + base : " ") + " " + plain.substr(0, path_length);
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
			menu_selected_							= items.empty() ? 0 : (std::min)(menu_selected_, items.size() - 1);
			if (menu_selected_ < form_scroll_)
				form_scroll_ = menu_selected_;
			if (menu_selected_ >= form_scroll_ + body)
				form_scroll_ = menu_selected_ + 1 - body;
			std::string crumbs = " Settings";
			for (const char c : menu_path_)
				crumbs += c == '.' ? std::string(" > ") : std::string(1, c);
			rows[1] = styled(kDim, crumbs);
			const size_t label_width = (std::min)(columns / 2, size_t{34});
			for (size_t row = 0; row < body && form_scroll_ + row < items.size(); ++row)
			{
				const size_t		index = form_scroll_ + row;
				const OutlineEntry& entry = outline[items[index]];
				std::string			text;
				if (!entry.leaf)
				{
					std::string name = entry.key;
					if (!name.empty() && name.front() == '[')
						for (size_t i = items[index] + 1; i < outline.size() && outline[i].depth > entry.depth; ++i)
							if (outline[i].leaf && outline[i].depth == entry.depth + 1 && outline[i].key == "name")
							{
								name += " " + outline[i].value;
								break;
							}
					const std::string fitted = fit(name, columns > 8 ? columns - 8 : 1);
					text					 = "   " + fitted + std::string(columns > 8 + fitted.size() ? columns - 8 - fitted.size() : 0, ' ') + " >";
				}
				else
				{
					const std::vector<std::string> options = value_choices(entry);
					if (options.size() == 2 && options[0] == "true")
					{
						std::string value = entry.value;
						if (value.size() >= 2 && (value.front() == '"' || value.front() == '\''))
							value = value.substr(1, value.size() - 2);
						text = std::string(" [") + (value == "true" ? "x" : " ") + "] " + entry.key;
					}
					else if (!entry.path.empty() && entry.path.back() == ']')
						text = "   " + entry.value;
					else
					{
						const std::string name = fit(entry.key, label_width);
						text = "   " + name + std::string(label_width > name.size() ? label_width - name.size() : 0, ' ') + "  " + entry.value;
					}
				}
				rows[2 + row] = styled(index == menu_selected_ ? kReverse : "", fit(text, columns));
			}
			if (items.empty() && body > 0)
				rows[2] = styled(kDim, "   (empty)");
			rows[total - 1] = styled(kDim, " Up/Down select  Enter/Right open or edit  Space toggle  Left/Esc back  Ctrl+S save  Ctrl+R run  Tab raw");
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
				const size_t index = raw_scroll_ + row;
				const std::string line = index < lines_.size() ? lines_[index] : std::string();
				char			  number[16];
				std::snprintf(number, sizeof(number), "%4zu ", index + 1);
				const size_t offset = index == cursor_row_ && cursor_column_ >= text_width ? cursor_column_ + 1 - text_width : 0;
				std::string	 shown	= offset < line.size() ? line.substr(offset) : std::string();
				std::string	 out	= std::string(kDim) + number + kReset;
				if (index == cursor_row_)
				{
					const size_t at = cursor_column_ - offset;
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
		rows[total - 2] = text_prompt ? std::string(kBold) + fit(" " + prompt_.label + ": " + prompt_.text, columns - 1) + kReverse + " " + kReset
									  : styled(kBold, " " + prompt_.label);
		if (text_prompt)
			rows[total - 1] = styled(kDim, " Enter confirm  Esc cancel");
	}
	else if (!message_.empty())
		rows[total - 2] = styled(message_is_error_ ? kRed : kGreen, " " + message_);

	std::string frame;
	for (size_t row = 0; row < rows.size(); ++row)
		frame += "\033[" + std::to_string(row + 1) + ";1H" + rows[row] + kReset;
	if (prompt_.kind == Prompt::Kind::edit_value && columns >= 12 && total >= 9)
	{
		// a centred dialog; the tail of a long value stays visible next to the cursor
		const size_t width	= (std::min)(columns - 4, size_t{64});
		const size_t inner	= width - 4;
		const size_t left	= (columns - width) / 2 + 1;
		const size_t top	= (total - 7) / 2 + 1;
		const std::string value = prompt_.text.size() >= inner ? prompt_.text.substr(prompt_.text.size() - (inner - 1)) : prompt_.text;
		const auto line = [&](const std::string& content, const char* style) {
			return std::string(style) + "| " + fit(content, inner) + " |" + kReset;
		};
		const std::vector<std::string> box = {
			std::string(kBold) + "+" + std::string(width - 2, '-') + "+" + kReset,
			line("Edit value", kBold),
			line(prompt_.label, kDim),
			std::string(kReverse) + "| " + fit(value, inner - 1) + " " + " |" + kReset,
			line("", ""),
			line("Enter confirm  Esc cancel", kDim),
			std::string(kBold) + "+" + std::string(width - 2, '-') + "+" + kReset,
		};
		for (size_t i = 0; i < box.size(); ++i)
			frame += "\033[" + std::to_string(top + i) + ";" + std::to_string(left) + "H" + box[i];
	}
	return frame;
}

}  // namespace config_tui

#endif
