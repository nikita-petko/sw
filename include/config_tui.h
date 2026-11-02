#ifndef CONFIG_TUI_H_
#define CONFIG_TUI_H_

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <vector>

/// Terminal UI that creates and edits profile files, see pocs/config_tui.md. Everything except session.cc is free of
/// terminal and engine dependencies: the views are a state machine (App) fed with keys that renders frames as strings.
namespace config_tui {

/// Result of checking one profile file.
enum class FileState
{
	ok,
	/// The file does not exist (anymore).
	missing,
	/// The file exists but cannot be read, or does not load as a profile file.
	unreadable,
};

struct FileStatus
{
	FileState	state = FileState::ok;
	/// What is wrong; for an unreadable file the first complaint of the loader (with its line).
	std::string message;
};

/// Loads the profile file at `path` with the production loader; returns the first complaint, or an empty string when
/// the file is valid.
using Validator = std::function<std::string(const std::string& path)>;

/// Checks that the file exists, can be read and passes `validate`.
FileStatus probe_file(const std::string& path, const Validator& validate);

/// A file that was opened or created before.
struct RecentEntry
{
	std::string path;
	/// UTC time of the last time the file was opened, `YYYY-MM-DDTHH:MM:SSZ`.
	std::string last_opened;
};

/// Longest recent list that is kept.
inline constexpr size_t kMaxRecent = 20;

/// Location of the shared recent-files list inside the per-user config directory; empty when the directory is unknown.
std::string recent_files_path(const std::string& config_directory);
/// Reads the list; a missing or unparsable file gives an empty list, never an error.
std::vector<RecentEntry> load_recent(const std::string& file);
/// Replaces the file atomically (temp file and rename), creating the directory when needed. Returns false on failure.
bool save_recent(const std::string& file, const std::vector<RecentEntry>& entries);
/// Moves `path` to the front (adding it when new), dropping duplicates and everything beyond kMaxRecent.
void add_recent(std::vector<RecentEntry>& entries, const std::string& path, const std::string& timestamp);
/// Absolute, lexically normalized form of a path, so the same file is never listed twice.
std::string absolute_path(const std::string& path);
/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
std::string utc_timestamp();

/// One line of the form view: a section header or a `key: value` / `- value` line of the profile file.
struct OutlineEntry
{
	/// Index of the line in the file.
	size_t		line = 0;
	/// Nesting depth, for indenting the view.
	int			depth = 0;
	/// Section headers have no value and cannot be edited.
	bool		leaf = false;
	/// Dotted path such as `profiles[1].delay_ms`.
	std::string path;
	/// Last path component without the index, such as `delay_ms`.
	std::string key;
	/// The value as written (quotes included); empty for headers.
	std::string value;
	/// Byte range of the value within the line; a trailing comment lies outside of it.
	size_t		value_begin = 0;
	size_t		value_end	= 0;
};

/// Reads the structure of a profile file line by line. Comments and blank lines are skipped.
std::vector<OutlineEntry> build_outline(const std::vector<std::string>& lines);
/// Returns `line` with the value of `entry` replaced; the key, indentation and trailing comment are kept.
std::string replace_value(const std::string& line, const OutlineEntry& entry, const std::string& value);
/// The values the setting accepts when it is a boolean or has a fixed set of values; empty otherwise.
std::vector<std::string> value_choices(const OutlineEntry& entry);

/// Minimal profile used by "New profile"; it loads without complaints.
const char* new_profile_template();

/// What the caller has to do after the UI finished.
enum class Outcome
{
	running,
	/// Leave the program.
	quit,
	/// Back to what was running; nothing was changed.
	cancel,
	/// Start (or restart) with the chosen file.
	run,
};

/// Outside services of the UI, replaceable in tests.
struct Services
{
	/// Shared recent-files list; empty keeps the list in memory only.
	std::string					 recent_file;
	/// The production loader.
	Validator					 validate;
	std::function<std::string()> now = utc_timestamp;
};

/// The loader and editor views. Feed it keys with handle_key() and draw render() whenever revision() changes.
class App
{
public:
	/// Opens the loader view, or the editor on `current_file` when given (swapping back from a running program).
	App(Services services, std::optional<std::string> current_file = std::nullopt);

	void		handle_key(int key);
	/// Draws the whole view as `height` rows of at most `width` columns (a string of cursor movements and text).
	std::string render(int width, int height);

	Outcome				outcome() const { return outcome_; }
	/// The file to run once the outcome is Outcome::run.
	const std::string&	chosen_path() const { return chosen_path_; }
	/// Changes on every key that altered what is shown.
	unsigned			revision() const { return revision_; }

	enum class Screen
	{
		loader,
		editor,
	};
	enum class Tab
	{
		form,
		raw,
	};
	Screen								screen() const { return screen_; }
	Tab									tab() const { return tab_; }
	const std::vector<RecentEntry>&		recent() const { return recent_; }
	const std::vector<FileStatus>&		statuses() const { return statuses_; }
	size_t								selected() const { return selected_; }
	const std::vector<std::string>&		lines() const { return lines_; }
	const std::string&					file_path() const { return file_path_; }
	bool								dirty() const { return dirty_; }
	const std::string&					message() const { return message_; }
	bool								prompting() const { return prompt_.kind != Prompt::Kind::none; }
	/// Cursor of the raw tab.
	size_t								cursor_row() const { return cursor_row_; }
	size_t								cursor_column() const { return cursor_column_; }

private:
	struct Prompt
	{
		enum class Kind
		{
			none,
			open_path,
			new_path,
			edit_value,
			confirm_discard,
			confirm_save_invalid,
			confirm_missing,
		};
		Kind		kind = Kind::none;
		std::string label;
		std::string text;
	};

	void   key_loader(int key);
	void   key_editor(int key);
	void   key_form(int key);
	void   key_raw(int key);
	void   key_prompt(int key);
	void   activate_selected();
	void   run_selected();
	void   refresh_statuses();
	bool   open_file(const std::string& requested);
	void   start_new(const std::string& path);
	bool   save(bool force);
	bool   save_and_run();
	void   remember(const std::string& path);
	void   forget_selected();
	void   leave_editor();
	void   pin_error(const std::string& error);
	void   begin_prompt(Prompt::Kind kind, const std::string& label, const std::string& text = {});
	void   change() { ++revision_; }
	void   touch() { dirty_ = true; }
	std::string text() const;
	size_t selectable_count() const { return recent_.size() + 2; }

	Services	services_;
	bool		swapped_in_;
	Outcome		outcome_ = Outcome::running;
	std::string chosen_path_;
	unsigned	revision_ = 1;
	Screen		screen_	  = Screen::loader;
	Tab			tab_	  = Tab::form;
	Prompt		prompt_;
	std::string message_;
	bool		message_is_error_ = false;

	std::vector<RecentEntry> recent_;
	std::vector<FileStatus>	 statuses_;
	size_t					 selected_ = 0;
	size_t					 list_scroll_ = 0;

	std::string				 file_path_;
	std::vector<std::string> lines_;
	bool					 dirty_			= false;
	bool					 crlf_			= false;
	bool					 backed_up_		= false;
	size_t					 form_selected_ = 0;
	size_t					 form_scroll_	= 0;
	size_t					 cursor_row_	= 0;
	size_t					 cursor_column_ = 0;
	size_t					 raw_scroll_	= 0;
	int						 page_rows_		= 10;
};

/// What session.cc reports back to the program.
struct Choice
{
	Outcome		outcome = Outcome::quit;
	std::string path;
};

/// Shows the loader/editor full screen and blocks until the user decides. `current_file` is set when swapping back
/// from a running program, and opens the editor on that file.
Choice run(const std::optional<std::string>& current_file);

}  // namespace config_tui

#endif
