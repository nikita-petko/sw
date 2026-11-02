#ifndef OPTIONS_H_
#define OPTIONS_H_

#include <string>

#include "packet_engine.h"

/// Parses command-line arguments and configuration files into engine options.
/// Returns false when parsing or validation fails, or when the arguments only asked for information (--help).
///
/// `config_override`, when not null, is loaded instead of the file named by --config (the other arguments still apply
/// on top of it). Without --config and without an override the file is required, unless `config_missing` is given and
/// the config TUI is available (compiled in and running on a terminal): the call then succeeds with `config_missing`
/// set and no profile loaded, and the caller has to pick a file and parse again with it as the override.
bool parse_options(int argc, char* argv[], PacketEngineOptions& options, const std::string* config_override = nullptr, bool* config_missing = nullptr);

/// Loads and validates a profiles file the way parse_options() does, without touching anything else. Returns the first
/// complaint, or an empty string when the file is fine.
std::string check_profiles_file(const std::string& path);

#endif