/*
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Manalyze is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "CLI11.hpp"

#include "cli.h"
#include "manalyze_version.h"
#include "hash-library/hash.h"
#include "manacommons/color.h"
#include "yara/yara_wrapper.h"

#if defined WITH_OPENSSL
# include <openssl/opensslv.h>
#endif


namespace {

std::vector<std::string> split_comma_values(const std::vector<std::string>& values)
{
    std::vector<std::string> out;
    for (const auto& value : values) {
        std::string current;
        for (const char ch : value) {
            if (ch == ',') {
                if (!current.empty()) {
                    out.push_back(current);
                    current.clear();
                }
                continue;
            }
            current.push_back(ch);
        }
        if (!current.empty()) {
            out.push_back(current);
        }
    }
    return out;
}

void print_help_default(const CLI::App& app, const std::string& argv_0)
{
    (void)argv_0;
    std::cout << app.help() << std::endl;
}

} // namespace

bool parse_args(Options& opts, int argc, char**argv, const HelpPrinter& help_printer, const ArgsValidator& validator)
{
    CLI::App app("Usage");
    app.allow_extras(false);
    app.set_help_flag("-h,--help", "Displays this message.");
    app.add_flag("-v,--version", opts.version, "Prints the program's version.");
    app.add_option("pe", opts.pe, "The PE to analyze. Multiple files may be specified.")
        ->expected(-1)
        ->required()
        ->type_name("FILE");
    app.add_flag("-r,--recursive", opts.recursive, "Scan all files in a directory (subdirectories will be ignored).");
    auto* output_opt = app.add_option("-o,--output", opts.output, "The output format. May be 'raw' (default) or 'json'.");
    auto* dump_opt = app.add_option("-d,--dump", opts.dump,
        "Dump PE information. Available choices are any combination of: "
        "all, summary, dos (dos header), pe (pe header), opt (pe optional header), sections, "
        "imports, exports, resources, version, debug, tls, config (image load configuration), "
        "delay (delay-load table), rich");
    dump_opt->expected(1);
    dump_opt->multi_option_policy(CLI::MultiOptionPolicy::TakeAll);
    app.add_flag("--hashes", opts.hashes, "Calculate various hashes of the file (may slow down the analysis!)");
    auto* extract_opt = app.add_option("-x,--extract", opts.extract, "Extract the PE resources and authenticode certificates "
        "to the target directory.");
    auto* plugins_opt = app.add_option("-p,--plugins", opts.plugins,
        "Analyze the binary with additional plugins. (may slow down the analysis!)");
    plugins_opt->expected(1);
    plugins_opt->multi_option_policy(CLI::MultiOptionPolicy::TakeAll);

    try
    {
        app.parse(argc, argv);
    }
    catch (const CLI::CallForHelp& e)
    {
        (void)e;
        if (help_printer) {
            help_printer(app, argv[0]);
        } else {
            print_help_default(app, argv[0]);
        }
        exit(0);
    }
    catch (const CLI::ParseError& e)
    {
        PRINT_ERROR << "Could not parse the command line (" << e.what() << ")." << std::endl << std::endl;
        return false;
    }

    opts.output_set = output_opt->count() > 0;
    opts.extract_set = extract_opt->count() > 0;
    opts.dump = split_comma_values(opts.dump);
    opts.plugins = split_comma_values(opts.plugins);

    if (opts.version)
    {
        std::stringstream ss;
        ss << "Manalyze " MANALYZE_VERSION " (Ivan Kwiatkowski, GPLv3 License) compiled with:" << std::endl;
        ss << "* Yara " << YR_MAJOR_VERSION << "." << YR_MINOR_VERSION << "." << YR_MICRO_VERSION << ". (Victor M. Alvarez, Apache 2.0 License)" << std::endl;
        ss << "* hash-library " << HASH_LIBRARY_VERSION << " (Stephan Brumme, ZLib License)." << std::endl;
        #if defined WITH_OPENSSL
            ss << "* " << OPENSSL_VERSION_TEXT << " (OpenSSL Project, OpenSSL License)" << std::endl;
        #endif
        std::cout << ss.str();
        exit(0);
    }
    else if (opts.pe.empty())
    {
        if (help_printer) {
            help_printer(app, argv[0]);
        } else {
            print_help_default(app, argv[0]);
        }
        exit(0);
    }

    if (validator) {
        return validator(opts, app, argv);
    }
    return true;
}
