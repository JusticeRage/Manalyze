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

#include "output_tree_node.h"

namespace io
{

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

}