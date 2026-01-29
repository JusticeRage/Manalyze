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

#include <boost/test/unit_test.hpp>

#include <filesystem>
#include <string>
#include <vector>

#include "cli.h"

namespace {

std::string test_file()
{
    const auto root = std::filesystem::current_path();
    return (root / "test" / "testfiles" / "manatest.exe").string();
}

std::vector<std::string> build_args(const std::vector<std::string>& args)
{
    std::vector<std::string> out;
    out.reserve(args.size() + 1);
    out.push_back("manalyze");
    out.insert(out.end(), args.begin(), args.end());
    return out;
}

bool parse_ok(const std::vector<std::string>& args, Options& opts)
{
    auto no_help = [](const CLI::App&, const std::string&) {};
    auto no_validate = [](const Options&, const CLI::App&, char**) { return true; };

    std::vector<char*> argv;
    argv.reserve(args.size());
    for (const auto& s : args) {
        argv.push_back(const_cast<char*>(s.c_str()));
    }

    return parse_args(opts, static_cast<int>(argv.size()), argv.data(), no_help, no_validate);
}

} // namespace

BOOST_AUTO_TEST_CASE(cli_parsing_examples)
{
    const std::string input = test_file();

    {
        Options opts;
        auto args = build_args({"-dresources", "-dexports", input});
        BOOST_CHECK(parse_ok(args, opts));
        BOOST_CHECK_EQUAL(opts.dump.size(), 2U);
        BOOST_CHECK_EQUAL(opts.dump[0], "resources");
        BOOST_CHECK_EQUAL(opts.dump[1], "exports");
    }

    {
        Options opts;
        auto args = build_args({"--dump=imports,sections", "--hashes", input});
        BOOST_CHECK(parse_ok(args, opts));
        BOOST_CHECK_EQUAL(opts.dump.size(), 2U);
        BOOST_CHECK_EQUAL(opts.dump[0], "imports");
        BOOST_CHECK_EQUAL(opts.dump[1], "sections");
        BOOST_CHECK(opts.hashes);
    }

    {
        Options opts;
        auto args = build_args({"-o", "json", "-d", "all", input});
        BOOST_CHECK(parse_ok(args, opts));
        BOOST_CHECK_EQUAL(opts.output, "json");
        BOOST_CHECK(opts.output_set);
        BOOST_CHECK_EQUAL(opts.dump.size(), 1U);
        BOOST_CHECK_EQUAL(opts.dump[0], "all");
    }

    {
        Options opts;
        auto args = build_args({input, "-o", "json", "-d", "all"});
        BOOST_CHECK(parse_ok(args, opts));
        BOOST_CHECK_EQUAL(opts.output, "json");
        BOOST_CHECK(opts.output_set);
        BOOST_CHECK_EQUAL(opts.dump.size(), 1U);
        BOOST_CHECK_EQUAL(opts.dump[0], "all");
        BOOST_CHECK_EQUAL(opts.pe.size(), 1U);
        BOOST_CHECK_EQUAL(opts.pe[0], input);
    }

    {
        Options opts;
        auto args = build_args({"-ojson", "-dall", input});
        BOOST_CHECK(parse_ok(args, opts));
        BOOST_CHECK_EQUAL(opts.output, "json");
        BOOST_CHECK(opts.output_set);
        BOOST_CHECK_EQUAL(opts.dump.size(), 1U);
        BOOST_CHECK_EQUAL(opts.dump[0], "all");
    }

    {
        Options opts;
        auto args = build_args({"-p", "virustotal", input, "-d", "all"});
        BOOST_CHECK(parse_ok(args, opts));
        BOOST_CHECK_EQUAL(opts.plugins.size(), 1U);
        BOOST_CHECK_EQUAL(opts.plugins[0], "virustotal");
        BOOST_CHECK_EQUAL(opts.dump.size(), 1U);
        BOOST_CHECK_EQUAL(opts.dump[0], "all");
        BOOST_CHECK_EQUAL(opts.pe.size(), 1U);
        BOOST_CHECK_EQUAL(opts.pe[0], input);
    }

    {
        Options opts;
        auto args = build_args({"-pvirustotal", input, "-dall"});
        BOOST_CHECK(parse_ok(args, opts));
        BOOST_CHECK_EQUAL(opts.plugins.size(), 1U);
        BOOST_CHECK_EQUAL(opts.plugins[0], "virustotal");
        BOOST_CHECK_EQUAL(opts.dump.size(), 1U);
        BOOST_CHECK_EQUAL(opts.dump[0], "all");
        BOOST_CHECK_EQUAL(opts.pe.size(), 1U);
        BOOST_CHECK_EQUAL(opts.pe[0], input);
    }
}
