/*
This file is part of Spike Guard.

Spike Guard is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Spike Guard is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Spike Guard.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "output_formatter.h"

namespace io {

// ----------------------------------------------------------------------------

int determine_max_width(pNode node)
{
	if (node->get_type() != OutputTreeNode::LIST)
	{
		PRINT_WARNING << "[RawFormatter] Tried to get the maximum width, but is not a list of nodes!" << std::endl;
		return 0;
	}
	unsigned int max = 0;
	nodes children = node->get_children();
	for (nodes::const_iterator it = children.begin() ; it != children.end() ; ++it) 
	{
		if ((*it)->get_type() == OutputTreeNode::LIST) {
			continue; // Ignore lists as they have no impact on alignment.
		}

		if ((*it)->get_name().length() > max) {
			max = (*it)->get_name().length();
		}
	}
	return max;
}

// ----------------------------------------------------------------------------

boost::optional<pNode> OutputTreeNode::find_node(const std::string& name) const
{
	if (_type != LIST)
	{
		PRINT_WARNING << "[OutputFormatter] Tried to search for a node, but is not a list of nodes!" << std::endl;
		return boost::optional<pNode>();
	}
	if (!_list_data || _list_data->size() == 0) {
		return boost::optional<pNode>();
	}

	nodes::const_iterator it;
	for (it = _list_data->begin(); it != _list_data->end(); ++it)
	{
		if ((*it)->get_name() == name) {
			break;
		}
	}

	if (it == _list_data->end()) {
		return boost::optional<pNode>();
	}
	else {
		return *it;
	}
}

// ----------------------------------------------------------------------------

void RawFormatter::format(std::ostream& sink)
{
	if (_header != "") {
		sink << _header << std::endl << std::endl;
	}

	nodes n = _root->get_children();
	for (nodes::const_iterator it = n.begin() ; it != n.end() ; ++it) // File level
	{
		_dump_node(sink, *it, determine_max_width(*it));
	}
}

// ----------------------------------------------------------------------------

void RawFormatter::_dump_node(std::ostream& sink, pNode node, int max_width, int level)
{
	if (node->get_name() == "Plugins") // Handle plugin output separately.
	{
		_dump_plugin_node(sink, node);
		return;
	}

	if (level == 0) // File level
	{
		sink << "-------------------------------------------------------------------------------" << std::endl;
		sink << node->get_name() << std::endl;
		sink << "-------------------------------------------------------------------------------" << std::endl << std::endl;
	}
	else if (level == 1) // Category level
	{
		if (node->get_type() != OutputTreeNode::LIST)
		{
			PRINT_WARNING << "[RawFormatter] Root element of an analysis is not a list!" << std::endl;
			return;
		}
		sink << node->get_name() << ":" << std::endl << std::string(node->get_name().length() + 1, '-') << std::endl;
	}
	else if (level == 2) 
	{
		sink << node->get_name();
		if (node->get_type() == OutputTreeNode::LIST) {
			sink << ":" << std::endl;
		}
	}
	else 
	{
		sink << std::string((level - 2) * 4, ' ') << node->get_name();
		if (node->get_type() == OutputTreeNode::LIST) {
			sink << ":" << std::endl;
		}
	}

	switch (node->get_type())
	{
		case OutputTreeNode::LIST:
			{ // New scope to be able to declare the "children" variable.
				// Determine children's max width
				nodes children = node->get_children();
				for (nodes::const_iterator it = children.begin(); it != children.end(); ++it) 
				{
					// Dump all children with an increased indentation level.
					if ((*it)->get_type() == OutputTreeNode::LIST) {
						_dump_node(sink, *it, determine_max_width(*it), level + 1);
					}
					else {
						_dump_node(sink, *it, max_width, level + 1);
					}
				}
				sink << std::endl;
			}
			break;

		case OutputTreeNode::STRINGS:
			{ // New scope to be able to declare the "strs" variable.
				strings strs = node->get_strings();
				if (strs.size() == 0) // Special case : empty array of strings.
				{
					if (max_width > 0) {
						sink << ": " << std::string(max_width - node->get_name().length(), ' ') << "(EMPTY)" << std::endl;
					}
					else {
						sink << ": (EMPTY)" << std::endl;
					}
					break;
				}

				for (strings::const_iterator it = strs.begin() ; it != strs.end() ; ++it)
				{
					if (max_width > 0) 
					{
						if (it == strs.begin()) {
							sink << ": " << std::string(max_width - node->get_name().length(), ' ') << *it << std::endl;
						}
						else {
							sink << std::string(max_width + 2 + (level - 2) * 4, ' ') << *it << std::endl;
						}
					}
					else 
					{
						if (it == strs.begin()) {
							sink << ": " << *it << std::endl;
						}
						else {
							sink << ": " << *it << std::endl;
						}
					}
				}
				
				break;
			}

		default:
			if (max_width > 0) {
				sink << ": " << std::string(max_width - node->get_name().length(), ' ') << node->to_string() << std::endl;
			}
			else {
				sink << ": " << node->to_string() << std::endl;
			}
			break;
	}
}

// ----------------------------------------------------------------------------

void RawFormatter::_dump_plugin_node(std::ostream& sink, pNode node)
{
	if (node->get_type() != OutputTreeNode::LIST)
	{
		PRINT_WARNING << "[RawFormatter] Plugins node is not a LIST!" << std::endl;
		return;
	}

	nodes plugin_nodes = node->get_children();
	for (nodes::const_iterator it = plugin_nodes.begin() ; it != plugin_nodes.end() ; ++it)
	{
		boost::optional<pNode> level = (*it)->find_node("level");
		boost::optional<pNode> summary = (*it)->find_node("summary");
		boost::optional<pNode> info = (*it)->find_node("plugin_output");
		if (!info)
		{
			PRINT_WARNING << "[RawFormatter] No output for plugin " << (*it)->get_name() << "!" << std::endl;
			continue;
		}

		if (level)
		{
			switch ((*level)->get_level())
			{
			case plugin::Result::NO_OPINION:
				break;

			case plugin::Result::MALICIOUS:
				utils::print_colored_text("MALICIOUS", utils::RED, sink, "[ ", " ] ");
				break;

			case plugin::Result::SUSPICIOUS:
				utils::print_colored_text("SUSPICIOUS", utils::YELLOW, sink, "[ ", " ] ");
				break;

			case plugin::Result::SAFE:
				utils::print_colored_text("SAFE", utils::GREEN, sink, "[ ", " ] ");
				break;
			}
		}

		if (summary) {
			sink << (*summary)->to_string() << std::endl;
		}
		else if ((*level)->get_level() != plugin::Result::NO_OPINION) {
			sink << std::endl;
		}
		strings output = (*info)->get_strings();
		for (std::vector<std::string>::iterator it2 = output.begin() ; it2 != output.end() ; ++it2) {
			sink << "\t" << *it2 << std::endl;
		}
		if (summary || output.size() > 0) {
			sink << std::endl;
		}
	}
}

// ----------------------------------------------------------------------------

std::string uint64_to_version_number(boost::uint32_t msbytes, boost::uint32_t lsbytes)
{
	std::stringstream ss;
	ss << ((msbytes >> 16) & 0xFFFF) << "." << (msbytes & 0xFFFF) << ".";
	ss << ((lsbytes >> 16) & 0xFFFF) << "." << (lsbytes & 0xFFFF);
	return ss.str();
}

// ----------------------------------------------------------------------------

std::string timestamp_to_string(boost::uint64_t epoch_timestamp)
{
	static std::locale loc(std::cout.getloc(), new boost::posix_time::time_facet("%Y-%b-%d %H:%M:%S%F %z"));
	std::stringstream ss;
	ss.imbue(loc);
	ss << boost::posix_time::from_time_t(epoch_timestamp);
	return ss.str();
}

} // !namespace io