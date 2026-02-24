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

#include <sstream>
#include <string>

#include "output_formatter.h"

namespace
{

io::pNode make_category(const std::string& name)
{
    return io::pNode(new io::OutputTreeNode(name, io::OutputTreeNode::LIST));
}

io::pNode make_summary_node(const std::string& value)
{
    return io::pNode(new io::OutputTreeNode("summary", value));
}

} // namespace

BOOST_AUTO_TEST_CASE(json_formatter_trims_and_escapes_values)
{
    io::JsonFormatter formatter;
    std::stringstream sink;

    io::pNode category = make_category("metadata");
    category->append(io::pNode(new io::OutputTreeNode("title", "   \"quoted\"   ")));

    io::pNode tags(new io::OutputTreeNode("tags", io::OutputTreeNode::STRINGS));
    tags->append("  first  ");
    tags->append(" second ");
    category->append(tags);

    category->append(io::pNode(new io::OutputTreeNode("magic", static_cast<std::uint32_t>(0x2A), io::OutputTreeNode::HEX)));

    formatter.add_data(category, "sample.bin");
    formatter.format(sink, true);

    const std::string output = sink.str();
    BOOST_CHECK_NE(output.find("\"title\": \"\\\"quoted\\\"\""), std::string::npos);
    BOOST_CHECK_NE(output.find("\"first\""), std::string::npos);
    BOOST_CHECK_NE(output.find("\"second\""), std::string::npos);
    BOOST_CHECK_NE(output.find("\"magic\": 42"), std::string::npos);
    BOOST_CHECK_EQUAL(output.find("\"magic\": 0x"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(json_formatter_keeps_comma_when_flushing)
{
    io::JsonFormatter formatter;
    std::stringstream sink;

    formatter.add_data(make_summary_node("first"), "first.bin");
    formatter.format(sink, false);

    formatter.add_data(make_summary_node("second"), "second.bin");
    formatter.format(sink, true);

    const std::string output = sink.str();

    BOOST_CHECK_NE(output.find("\"first.bin\": {"), std::string::npos);
    BOOST_CHECK_NE(output.find("\"second.bin\": {"), std::string::npos);
    BOOST_CHECK_NE(output.find("},\n    \"second.bin\": {"), std::string::npos);
    BOOST_CHECK_EQUAL(output.find("}\n    \"second.bin\": {"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(raw_formatter_strings_empty_and_multiline)
{
    io::RawFormatter formatter;
    std::stringstream sink;

    io::pNode category = make_category("strings");

    io::pNode empty_strings(new io::OutputTreeNode("empty", io::OutputTreeNode::STRINGS));
    category->append(empty_strings);

    io::strings lines;
    lines.push_back("alpha");
    lines.push_back("beta");
    io::pNode multiline(new io::OutputTreeNode("multiline", lines, io::OutputTreeNode::NEW_LINE));
    category->append(multiline);

    formatter.add_data(category, "raw.bin");
    formatter.format(sink, true);

    const std::string output = sink.str();
    BOOST_CHECK_NE(output.find("empty:"), std::string::npos);
    BOOST_CHECK_NE(output.find("(EMPTY)"), std::string::npos);
    BOOST_CHECK_NE(output.find("multiline:\n    alpha\n    beta"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(raw_formatter_plugins_print_hidden_values_without_name)
{
    io::RawFormatter formatter;
    std::stringstream sink;

    io::pNode plugins = make_category("Plugins");
    io::pNode plugin_node = make_category("test-plugin");
    plugin_node->append(io::pNode(new io::OutputTreeNode("level", plugin::SAFE)));
    plugin_node->append(io::pNode(new io::OutputTreeNode("summary", "plugin summary")));

    io::pNode plugin_output = make_category("plugin_output");
    plugin_output->append(io::pNode(new io::OutputTreeNode("hidden_label", "secret", io::OutputTreeNode::HIDE_NAME)));
    plugin_output->append(io::pNode(new io::OutputTreeNode("visible_label", "shown")));
    plugin_node->append(plugin_output);
    plugins->append(plugin_node);

    formatter.add_data(plugins, "plugins.bin");
    formatter.format(sink, true);

    const std::string output = sink.str();
    BOOST_CHECK_NE(output.find("SAFE"), std::string::npos);
    BOOST_CHECK_NE(output.find("plugin summary"), std::string::npos);
    BOOST_CHECK_NE(output.find("    secret"), std::string::npos);
    BOOST_CHECK_NE(output.find("    visible_label: shown"), std::string::npos);
    BOOST_CHECK_EQUAL(output.find("hidden_label: secret"), std::string::npos);
}

BOOST_AUTO_TEST_CASE(uint64_to_version_number_formats_expected)
{
    BOOST_CHECK_EQUAL(io::uint64_to_version_number(0x00020003, 0x00040005), "2.3.4.5");
}
