#include "config_tui.h"

#ifdef LAGSW_FEATURE_CONFIG_TUI

#	include <cstdio>

#	include "log.h"
#	include "options.h"
#	include "platform.h"

namespace config_tui {

Choice run(const std::optional<std::string>& current_file)
{
	Services services;
	services.recent_file = recent_files_path(platform::config_directory());
	services.validate	 = [](const std::string& path) { return check_profiles_file(path); };
	App app(services, current_file);

	// Like the net monitor: the alternate screen, with log lines held back and the status lines kept at the bottom.
	logging::set_suspended(true);
	std::printf("\033[?1049h\033[?25l");
	std::fflush(stdout);

	int		 last_columns  = 0;
	int		 last_rows	   = 0;
	unsigned last_revision = 0;
	while (app.outcome() == Outcome::running)
	{
		const int  columns = platform::console_width() > 0 ? platform::console_width() : 80;
		const int  rows	   = platform::console_height() > 0 ? platform::console_height() : 24;
		const bool resized = columns != last_columns || rows != last_rows;
		if (resized || app.revision() != last_revision)
		{
			const int		  usable = rows - logging::pinned_status_rows(rows);
			const std::string frame	 = (resized ? "\033[2J" : "") + app.render(columns, usable);
			logging::write_frame(frame, rows);
			last_columns  = columns;
			last_rows	  = rows;
			last_revision = app.revision();
		}
		const int key = platform::read_edit_key();
		if (key == platform::edit_key::none)
			platform::sleep_ms(15);
		else
			app.handle_key(key);
	}

	std::printf("\033[?25h\033[?1049l");
	std::fflush(stdout);
	logging::set_suspended(false);
	return {app.outcome(), app.chosen_path()};
}

}  // namespace config_tui

#endif
