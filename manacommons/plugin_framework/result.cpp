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

#include "plugin_framework/result.h"

namespace plugin {

Result::Result(const std::string& plugin_name)
{
	_data = boost::make_shared<io::OutputTreeNode>(plugin_name, io::OutputTreeNode::LIST);
	_data->append(boost::make_shared<io::OutputTreeNode>("level", NO_OPINION));
	_data->append(boost::make_shared<io::OutputTreeNode>("plugin_output", io::OutputTreeNode::LIST));
}

// ----------------------------------------------------------------------------

void Result::set_level(LEVEL level)
{
	io::pNode opt_level = _data->find_node("level");
	if (!opt_level) // Should never happen.
	{
		PRINT_WARNING << "[Result] A result object has no level node. This should be investigated."
			<< DEBUG_INFO << std::endl;
		_data->append(boost::make_shared<io::OutputTreeNode>("level", level));
	}
	else {
		opt_level->update_value(level);
	}
}

// ----------------------------------------------------------------------------

void Result::raise_level(LEVEL level)
{
	io::pNode opt_level = _data->find_node("level");
	if (!opt_level) // Should never happen.
	{
		PRINT_WARNING << "[Result] A result object has no level node. This should be investigated."
			<< DEBUG_INFO << std::endl;
		_data->append(boost::make_shared<io::OutputTreeNode>("level", level));
	}
	else
	{
		if (level > opt_level->get_level()) {
			opt_level->update_value(level);
		}
	}
}

// ----------------------------------------------------------------------------

LEVEL Result::get_level() const
{
	io::pNode opt_level = _data->find_node("level");
	if (!opt_level) // Should never happen.
	{
		PRINT_WARNING << "[Result] A result object has no level node. This should be investigated."
			<< DEBUG_INFO << std::endl;
		return NO_OPINION;
	}
	else {
		return opt_level->get_level();
	}
}

// ----------------------------------------------------------------------------

void Result::set_summary(const std::string& s)
{
	io::pNode opt_summary = _data->find_node("summary");
	if (!opt_summary) {
		_data->append(boost::make_shared<io::OutputTreeNode>("summary", s));
	}
	else {
		opt_summary->update_value(s);
	}
}

// ----------------------------------------------------------------------------

pString Result::get_summary() const
{
	io::pNode opt_summary = _data->find_node("summary");
	if (!opt_summary) {
		return pString();
	}
	else {
		return opt_summary->to_string();
	}
}

// ----------------------------------------------------------------------------

io::pNode Result::get_information() const
{
	io::pNode output = _data->find_node("plugin_output");
	if (!output)
	{
		PRINT_WARNING << "[Result] A result object's output data wasn't initialized!"
			<< DEBUG_INFO << std::endl;
		output = boost::make_shared<io::OutputTreeNode>("plugin_output", io::OutputTreeNode::LIST);
		_data->append(output);
	}
	return output;
}

// ----------------------------------------------------------------------------

void Result::merge(const Result& res)
{
	raise_level(res.get_level());
	auto info = res.get_information();
	if (!info) {
		return;
	}
	auto children = info->get_children();
	if (!children) {
		return;
	}
	for (auto child : *children) {
		add_information(child);
	}
}

// ----------------------------------------------------------------------------

std::string Result::_create_node_name() const
{
	std::stringstream ss;
	ss << "info_";
	io::pNode info = get_information();
	if (info->get_children()) {
		ss << info->size();
	}
	else {
		ss << 0;
	}
	return ss.str();
}

// ----------------------------------------------------------------------------

/**
*	@brief	Template specialization for nodes.
*/
template<>
DECLSPEC_MANACOMMONS void Result::add_information(io::pNode node)
{
	io::pNode output = get_information();
	output->append(node);
}

} // !namespace plugin
