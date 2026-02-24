#pragma once

#include <functional>
#include <string>
#include <vector>

namespace CLI {
class App;
}

struct Options
{
    bool version = false;
    bool recursive = false;
    bool hashes = false;
    bool quiet = false;
    bool output_set = false;
    bool extract_set = false;
    bool log_level_set = false;
    std::string output;
    std::string extract;
    std::string log_level;
    std::vector<std::string> dump;
    std::vector<std::string> plugins;
    std::vector<std::string> pe;
};

using HelpPrinter = std::function<void(const CLI::App&, const std::string&)>;
using ArgsValidator = std::function<bool(const Options&, const CLI::App&, char**)>;

bool parse_args(Options& opts, int argc, char**argv, const HelpPrinter& help_printer, const ArgsValidator& validator);
