#ifndef OPTIONS_H_
#define OPTIONS_H_

#include "packet_engine.h"

/// Parses command-line arguments and configuration files into engine options.
/// Returns false when parsing or validation fails.
bool parse_options(int argc, char* argv[], PacketEngineOptions& options);

#endif