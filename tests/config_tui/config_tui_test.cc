// Tests for the profile loader/editor: the recent-files list, the outline of a profile file and both views driven with keys.
// Run from the project root: `xmake test config_tui_test`.
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "config_tui.h"
#include "log.h"
#include "options/internal.h"
#include "platform.h"
#include "support/test.h"

namespace {
namespace fs  = std::filesystem;
namespace key = platform::edit_key;
using namespace config_tui;

struct TempDirectory
{
	fs::path path;
	TempDirectory()
	{
		path = fs::temp_directory_path() / ("lagsw_config_tui_test_" + std::to_string(std::rand()));
		fs::remove_all(path);
		fs::create_directories(path);
	}
	~TempDirectory() { fs::remove_all(path); }
	std::string file(const std::string& name) const { return (path / name).string(); }
};

void write(const std::string& path, const std::string& content)
{
	std::ofstream(path, std::ios::binary) << content;
}

std::string read(const std::string& path)
{
	std::ifstream input(path, std::ios::binary);
	return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

/// The production loader, with its complaints captured.
std::string validate(const std::string& path)
{
	PacketEngineOptions options;
	logging::begin_capture();
	const bool				 ok		  = config::load_profiles(path.c_str(), options);
	std::vector<std::string> messages = logging::end_capture();
	if (ok)
		return {};
	return messages.empty() ? "invalid" : messages.front();
}

Services services_in(const TempDirectory& directory)
{
	Services services;
	services.recent_file = directory.file("config/recent.yml");
	services.validate	 = validate;
	services.now		 = [] { return std::string("2026-01-01T00:00:00Z"); };
	return services;
}

void type(App& app, const std::string& text)
{
	for (const char c : text)
		app.handle_key(c);
}

void test_recent_files_round_trip()
{
	TempDirectory	  directory;
	const std::string file = recent_files_path(directory.file("config"));
	CHECK(!file.empty() && recent_files_path("").empty());
	CHECK(load_recent(file).empty());
	std::vector<RecentEntry> entries;
	add_recent(entries, "/a/one.yml", "t1");
	add_recent(entries, "/b/odd \"name\": #1.yml", "t2");
	add_recent(entries, "/a/one.yml", "t3");
	CHECK(entries.size() == 2 && entries[0].path == "/a/one.yml" && entries[0].last_opened == "t3");
	CHECK(save_recent(file, entries));
	const std::vector<RecentEntry> loaded = load_recent(file);
	CHECK(loaded.size() == 2 && loaded[0].path == "/a/one.yml" && loaded[1].path == "/b/odd \"name\": #1.yml" &&
		  loaded[1].last_opened == "t2");
	for (int i = 0; i < 30; ++i)
		add_recent(entries, "/f/" + std::to_string(i), "t");
	CHECK(entries.size() == kMaxRecent);
}

void test_recent_files_bad_file_is_empty()
{
	TempDirectory	  directory;
	const std::string file = directory.file("recent.yml");
	write(file, "this is { not a recent list\n  - path: x\n");
	CHECK(load_recent(file).empty());
	write(file, "recent:\n  - path: \"/ok.yml\"\n  - bogus line\n  - path: \"\"\n");
	CHECK(load_recent(file).size() == 1);
}

void test_probe_file()
{
	TempDirectory directory;
	CHECK(probe_file(directory.file("nope.yml"), validate).state == FileState::missing);
	write(directory.file("good.yml"), new_profile_template());
	CHECK(probe_file(directory.file("good.yml"), validate).state == FileState::ok);
	write(directory.file("bad.yml"), "profiles:\n  - name: \"A\"\n    key: nonsense-key\n");
	const FileStatus bad = probe_file(directory.file("bad.yml"), validate);
	CHECK(bad.state == FileState::unreadable && bad.message.find("line 3") != std::string::npos);
	// a directory is not a profile file
	CHECK(probe_file(directory.path.string(), validate).state == FileState::missing);
}

void test_template_is_valid()
{
	TempDirectory directory;
	write(directory.file("t.yml"), new_profile_template());
	CHECK(validate(directory.file("t.yml")).empty());
}

void test_outline()
{
	const std::vector<std::string> lines = {
		"# comment",
		"default_view: log   # shown first",
		"servers:",
		"  addresses:",
		"    - \"10.0.0.1:name: x\"",
		"profiles:",
		"  - name: \"A\"",
		"    key: x",
		"    mode: toggle",
		"    enabled: true",
		"  - name: \"B\"",
		"    keys: [ctrl, shift, m]",
	};
	const std::vector<OutlineEntry> outline = build_outline(lines);
	const auto						find	= [&](const std::string& path) -> const OutlineEntry* {
		for (const OutlineEntry& entry : outline)
			if (entry.path == path)
				return &entry;
		return nullptr;
	};
	const OutlineEntry* view = find("default_view");
	CHECK(view && view->leaf && view->value == "log" && view->line == 1);
	CHECK(replace_value(lines[1], *view, "net_monitor") == "default_view: net_monitor   # shown first");
	CHECK(find("servers") && !find("servers")->leaf);
	const OutlineEntry* address = find("servers.addresses[0]");
	CHECK(address && address->leaf && address->value == "\"10.0.0.1:name: x\"");
	CHECK(find("profiles[0].name") && find("profiles[0].name")->value == "\"A\"");
	CHECK(find("profiles[1].name") && find("profiles[1].keys") && find("profiles[1].keys")->value == "[ctrl, shift, m]");
	CHECK(find("profiles[0].mode") && value_choices(*find("profiles[0].mode")).size() == 3);
	CHECK(value_choices(*find("profiles[0].enabled")) == (std::vector<std::string>{"true", "false"}));
	CHECK(value_choices(*find("profiles[0].key")).empty());
}

void test_loader_marks_missing_and_unreadable_files()
{
	TempDirectory directory;
	write(directory.file("good.yml"), new_profile_template());
	write(directory.file("bad.yml"), "profiles:\n  - name: \"A\"\n    key: nonsense-key\n");
	std::vector<RecentEntry> entries;
	add_recent(entries, directory.file("good.yml"), "t");
	add_recent(entries, directory.file("bad.yml"), "t");
	add_recent(entries, directory.file("gone.yml"), "t");
	const Services services = services_in(directory);
	CHECK(save_recent(services.recent_file, entries));

	App app(services);
	CHECK(app.screen() == App::Screen::loader && app.recent().size() == 3);
	CHECK(app.recent()[0].path == directory.file("gone.yml"));
	CHECK(app.statuses()[0].state == FileState::missing);
	CHECK(app.statuses()[1].state == FileState::unreadable);
	CHECK(app.statuses()[2].state == FileState::ok);
	const std::string frame = app.render(100, 20);
	CHECK(frame.find("\033[1;31m!") != std::string::npos);
	CHECK(frame.find("not found") != std::string::npos && frame.find("cannot read") != std::string::npos);
	CHECK(frame.find("+ New profile...") != std::string::npos);

	// a missing file offers to be removed from the list, which never touches files
	app.handle_key(key::enter);
	CHECK(app.prompting());
	app.handle_key('d');
	CHECK(!app.prompting() && app.recent().size() == 2 && load_recent(services.recent_file).size() == 2);

	// an unreadable file opens on its raw text with the complaint pinned to the line
	app.handle_key(key::enter);
	CHECK(app.screen() == App::Screen::editor && app.tab() == App::Tab::raw);
	CHECK(app.cursor_row() == 2 && app.message().find("line 3") != std::string::npos);
	CHECK(read(directory.file("bad.yml")).find("nonsense-key") != std::string::npos);
}

void test_loader_keys_and_outcomes()
{
	TempDirectory directory;
	write(directory.file("good.yml"), new_profile_template());
	const Services services = services_in(directory);
	{
		App app(services);
		app.handle_key('q');
		CHECK(app.outcome() == Outcome::quit);
	}
	{
		App app(services);
		app.handle_key(key::escape);
		CHECK(app.outcome() == Outcome::quit);
	}
	{
		App app(services, directory.file("good.yml"));
		CHECK(app.screen() == App::Screen::editor);
		app.handle_key(key::escape);
		CHECK(app.screen() == App::Screen::loader && app.recent().size() == 1);
		app.handle_key(key::escape);
		CHECK(app.outcome() == Outcome::cancel);
	}
	{
		App app(services);
		app.handle_key(key::ctrl('R'));
		CHECK(app.outcome() == Outcome::running);
		app.handle_key(' ');
		CHECK(app.outcome() == Outcome::run && app.chosen_path() == absolute_path(directory.file("good.yml")));
	}
}

void test_open_path_and_new_profile()
{
	TempDirectory  directory;
	const Services services = services_in(directory);
	App			   app(services);
	app.handle_key('o');
	type(app, directory.file("missing.yml"));
	app.handle_key(key::enter);
	CHECK(app.screen() == App::Screen::loader && app.message().find("Not found") != std::string::npos);

	app.handle_key('n');
	for (size_t i = 0; i < std::string("profiles/new.sw.yml").size(); ++i)
		app.handle_key(key::backspace);
	type(app, directory.file("made/new.sw.yml"));
	app.handle_key(key::enter);
	CHECK(app.screen() == App::Screen::editor && app.dirty() && !fs::exists(directory.file("made/new.sw.yml")));
	app.handle_key(key::ctrl('S'));
	CHECK(!app.dirty() && fs::exists(directory.file("made/new.sw.yml")));
	CHECK(validate(directory.file("made/new.sw.yml")).empty());
	CHECK(load_recent(services.recent_file).size() == 1);
	CHECK(!fs::exists(directory.file("made/new.sw.yml.lagsw-tmp")));
	app.handle_key(key::ctrl('R'));
	CHECK(app.outcome() == Outcome::run);

	// a name that exists is not overwritten by "new"
	App again(services);
	again.handle_key('n');
	for (size_t i = 0; i < std::string("profiles/new.sw.yml").size(); ++i)
		again.handle_key(key::backspace);
	type(again, directory.file("made/new.sw.yml"));
	again.handle_key(key::enter);
	CHECK(again.screen() == App::Screen::loader && again.message().find("already exists") != std::string::npos);
}

void test_form_editing_keeps_comments_and_makes_a_backup()
{
	TempDirectory	  directory;
	const std::string path = directory.file("p.yml");
	write(path, std::string(new_profile_template()) + "    # trailing comment\n");
	App app(services_in(directory), path);
	CHECK(app.tab() == App::Tab::form && !app.dirty());

	// default_view has fixed values, so Enter opens a drop-down rather than a text dialog
	app.handle_key(key::enter);
	CHECK(app.prompting());
	const std::string drop = app.render(100, 20);
	CHECK(drop.find("Select value") != std::string::npos && drop.find("net_monitor") != std::string::npos &&
		  drop.find("Edit value") == std::string::npos);
	app.handle_key(key::down);
	app.handle_key(key::escape);
	CHECK(!app.dirty() && app.lines()[1] == "default_view: log");
	app.handle_key(key::enter);
	app.handle_key(key::down);
	app.handle_key(key::enter);
	CHECK(app.dirty() && app.lines()[1] == "default_view: net_monitor");
	app.handle_key(key::enter);
	app.handle_key(key::up);
	app.handle_key(key::enter);
	CHECK(app.lines()[1] == "default_view: log");

	// the top menu lists sections as submenus; profiles > [0] > delay_ms opens the value dialog
	const std::string top = app.render(100, 20);
	CHECK(top.find("default_view") != std::string::npos && top.find(" >") != std::string::npos);
	CHECK(top.find("delay_ms") == std::string::npos);
	app.handle_key(key::down);
	app.handle_key(key::down);
	app.handle_key(key::enter);
	CHECK(app.render(100, 20).find("[0] \"Delay\"") != std::string::npos);
	app.handle_key(key::enter);
	const std::string profile = app.render(100, 20);
	CHECK(profile.find("delay_ms") != std::string::npos && profile.find("[x]") == std::string::npos);
	for (int i = 0; i < 4; ++i)
		app.handle_key(key::down);
	app.handle_key(key::enter);
	CHECK(app.prompting());
	const std::string dialog = app.render(100, 20);
	CHECK(dialog.find("Edit value") != std::string::npos && dialog.find("profiles[0].delay_ms") != std::string::npos);
	for (int i = 0; i < 3; ++i)
		app.handle_key(key::backspace);
	type(app, "250");
	app.handle_key(key::enter);
	bool changed = false;
	for (const std::string& line : app.lines())
		changed = changed || line == "    delay_ms: 250";
	CHECK(changed);

	// capture_options is a submenu of checkboxes; Enter toggles one and Esc steps back out
	app.handle_key(key::down);
	app.handle_key(key::down);
	app.handle_key(key::enter);
	const std::string boxes = app.render(100, 20);
	CHECK(boxes.find("[x] outbound") != std::string::npos && boxes.find("[x] inbound") != std::string::npos);
	app.handle_key(key::enter);
	CHECK(app.render(100, 20).find("[ ] outbound") != std::string::npos);
	app.handle_key(key::escape);
	CHECK(app.screen() == App::Screen::editor && app.render(100, 20).find("capture_options") != std::string::npos);
	app.handle_key(key::left);
	app.handle_key(key::left);
	CHECK(app.render(100, 20).find("profiles") != std::string::npos && app.render(100, 20).find("delay_ms") == std::string::npos);

	app.handle_key(key::ctrl('S'));
	CHECK(!app.dirty() && read(path).find("delay_ms: 250") != std::string::npos &&
		  read(path).find("# trailing comment") != std::string::npos);
	CHECK(fs::exists(path + ".bak") && read(path + ".bak").find("delay_ms: 100") != std::string::npos);
}

void test_invalid_save_needs_confirmation()
{
	TempDirectory	  directory;
	const std::string path = directory.file("p.yml");
	write(path, new_profile_template());
	App app(services_in(directory), path);
	app.handle_key(key::ctrl('T'));
	CHECK(app.tab() == App::Tab::raw);
	// go to the `key: x` line of the profile (line 10) and break its value
	while (app.cursor_row() < 9)
		app.handle_key(key::down);
	app.handle_key(key::end);
	type(app, "-oops");
	CHECK(app.lines()[9] == "    key: x-oops");
	app.handle_key(key::ctrl('S'));
	CHECK(app.prompting() && read(path).find("x-oops") == std::string::npos);
	app.handle_key('n');
	CHECK(!app.prompting() && app.dirty());
	app.handle_key(key::ctrl('R'));
	CHECK(app.outcome() == Outcome::running);
	app.handle_key('y');
	CHECK(app.outcome() == Outcome::running);
	app.handle_key(key::ctrl('S'));
	app.handle_key('y');
	CHECK(!app.dirty() && read(path).find("x-oops") != std::string::npos && app.message().find("Saved with errors") == 0);
	// the saved file is listed with a marker next to it
	app.handle_key(key::escape);
	CHECK(app.screen() == App::Screen::loader && app.statuses()[0].state == FileState::unreadable);
	app.handle_key(key::ctrl('R'));
	CHECK(app.outcome() == Outcome::running && app.message().find("cannot read") != std::string::npos);
}

void test_discarding_changes_is_confirmed()
{
	TempDirectory	  directory;
	const std::string path = directory.file("p.yml");
	write(path, new_profile_template());
	App app(services_in(directory), path);
	app.handle_key(key::enter);
	app.handle_key(key::down);
	app.handle_key(key::enter);
	app.handle_key(key::escape);
	CHECK(app.prompting() && app.screen() == App::Screen::editor);
	app.handle_key('n');
	CHECK(!app.prompting() && app.screen() == App::Screen::editor && app.dirty());
	app.handle_key(key::escape);
	app.handle_key('y');
	CHECK(app.screen() == App::Screen::loader);
	CHECK(read(path).find("default_view: log") != std::string::npos);
}

void test_raw_editing()
{
	TempDirectory	  directory;
	const std::string path = directory.file("p.yml");
	write(path, "a: 1\r\n  b: 2\r\n");
	App app(services_in(directory), path);
	// the file has no profiles, so it already opened on the raw tab
	CHECK(app.tab() == App::Tab::raw);
	app.handle_key(key::down);
	app.handle_key(key::end);
	app.handle_key(key::enter);
	CHECK(app.lines().size() == 3 && app.lines()[2] == "  ");
	type(app, "c: 3");
	app.handle_key(key::backspace);
	CHECK(app.lines()[2] == "  c: ");
	app.handle_key(key::home);
	app.handle_key(key::backspace);
	CHECK(app.lines()[1] == "  b: 2  c: " && app.lines().size() == 2);
	app.handle_key(key::ctrl('S'));
	app.handle_key('y');
	// the file keeps its CRLF line ends
	CHECK(read(path) == "a: 1\r\n  b: 2  c: \r\n");
}

void test_render_fits_the_screen()
{
	TempDirectory directory;
	write(directory.file("p.yml"), new_profile_template());
	App app(services_in(directory), directory.file("p.yml"));
	for (const int width : {20, 40, 120})
		for (const int height : {6, 10, 40})
		{
			CHECK(!app.render(width, height).empty());
			app.handle_key(key::ctrl('T'));
			CHECK(!app.render(width, height).empty());
		}
}
void test_reserved_key_is_rejected()
{
	TempDirectory directory;
	std::string	  profile = new_profile_template();
	write(directory.file("ok.yml"), profile);
	CHECK(validate(directory.file("ok.yml")).empty());
	write(directory.file("c.yml"), "profiles:\n  - name: \"A\"\n    key: I\n    mode: toggle\n");
	CHECK(validate(directory.file("c.yml")).find("reserved") != std::string::npos);
	write(directory.file("lower.yml"), "profiles:\n  - name: \"A\"\n    key: i\n    mode: toggle\n");
	CHECK(validate(directory.file("lower.yml")).find("reserved") != std::string::npos);
}
void test_list_entries_can_be_added_and_removed()
{
	TempDirectory	  directory;
	const std::string path = directory.file("p.yml");
	write(path, new_profile_template());
	App			 app(services_in(directory), path);
	const size_t original = app.lines().size();
	const auto	 count_of = [&](const std::string& needle) {
		size_t count = 0;
		for (const std::string& line : app.lines())
			count += line.find(needle) != std::string::npos;
		return count;
	};

	// the menu is a bordered box
	const std::string frame = app.render(100, 24);
	CHECK(frame.find("\u250c") != std::string::npos && frame.find("\u2514") != std::string::npos);

	// servers > addresses is a plain list: an add row ends it, and `a` asks for the value
	app.handle_key(key::down);
	app.handle_key(key::enter);
	app.handle_key(key::enter);
	CHECK(app.render(100, 24).find("+ Add item") != std::string::npos);
	app.handle_key('a');
	CHECK(app.prompting());
	type(app, "10.0.0.2:two");
	app.handle_key(key::enter);
	CHECK(count_of("    - \"10.0.0.2:two\"") == 1 && app.dirty() && app.lines().size() == original + 1);

	// Delete removes the selected entry after a confirmation
	app.handle_key(key::del);
	CHECK(app.prompting());
	app.handle_key('n');
	CHECK(count_of("10.0.0.2:two") == 1);
	app.handle_key(key::del);
	app.handle_key('y');
	CHECK(count_of("10.0.0.2:two") == 0 && app.lines().size() == original);

	// the add row works too
	app.handle_key(key::down);
	app.handle_key(key::enter);
	type(app, "10.0.0.3");
	app.handle_key(key::enter);
	CHECK(count_of("- 10.0.0.3") == 1);
	app.handle_key(key::left);
	app.handle_key(key::left);

	// profiles is a list of sections: adding one inserts a whole entry, removing one removes all its lines
	app.handle_key(key::down);
	app.handle_key(key::enter);
	app.handle_key('a');
	CHECK(!app.prompting() && count_of("- name:") == 2 && count_of("capture_options:") == 2);
	app.handle_key(key::del);
	app.handle_key('y');
	CHECK(count_of("- name:") == 1 && count_of("capture_options:") == 1);
	app.handle_key(key::up);
	CHECK(app.render(100, 24).find("[0]") != std::string::npos);
}
}  // namespace

int main(int argc, char** argv)
{
	static const test::TestCase cases[] = {
		{"recent_files_round_trip", test_recent_files_round_trip},
		{"recent_files_bad_file_is_empty", test_recent_files_bad_file_is_empty},
		{"probe_file", test_probe_file},
		{"template_is_valid", test_template_is_valid},
		{"outline", test_outline},
		{"loader_marks_missing_and_unreadable_files", test_loader_marks_missing_and_unreadable_files},
		{"loader_keys_and_outcomes", test_loader_keys_and_outcomes},
		{"open_path_and_new_profile", test_open_path_and_new_profile},
		{"form_editing_keeps_comments_and_makes_a_backup", test_form_editing_keeps_comments_and_makes_a_backup},
		{"invalid_save_needs_confirmation", test_invalid_save_needs_confirmation},
		{"discarding_changes_is_confirmed", test_discarding_changes_is_confirmed},
		{"raw_editing", test_raw_editing},
		{"render_fits_the_screen", test_render_fits_the_screen},
		{"reserved_key_is_rejected", test_reserved_key_is_rejected},
		{"list_entries_can_be_added_and_removed", test_list_entries_can_be_added_and_removed},
	};
	return test::run_tests("config_tui", cases, argc, argv);
}
