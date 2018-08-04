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

#include <iomanip>

#include "manacommons/output_tree_node.h"

namespace io
{

size_t determine_max_width(pNode node)
{
	if (node->get_type() != OutputTreeNode::LIST)
	{
		PRINT_WARNING << "[RawFormatter] Tried to get the maximum width, but is not a list of nodes!" << std::endl;
		return 0;
	}
	size_t max = 0;
	pNodes children = node->get_children();
	for (nodes::const_iterator it = children->begin() ; it != children->end() ; ++it)
	{
		if ((*it)->get_type() == OutputTreeNode::LIST) {
			continue; // Ignore lists as they have no impact on alignment.
		}

		if ((*it)->get_name()->length() > max) {
			max = (*it)->get_name()->length();
		}
	}
	return max;
}

// ----------------------------------------------------------------------------

pNode OutputTreeNode::find_node(const std::string& name) const
{
	if (_type != LIST)
	{
		PRINT_WARNING << "[OutputFormatter] Tried to search for a node, but is not a list of nodes!" << std::endl;
		return pNode();
	}

	if (!_list_data || !*_list_data || (*_list_data)->size() == 0) {
		return pNode();
	}

	nodes::const_iterator it;
	for (it = (*_list_data)->begin(); it != (*_list_data)->end(); ++it)
	{
		if (*(*it)->get_name() == name) {
			break;
		}
	}

	if (it == (*_list_data)->end()) {
		return pNode();
	}
	else {
		return *it;
	}
}

// ----------------------------------------------------------------------------

OutputTreeNode::OutputTreeNode(const std::string& name,
							   enum node_type type,
							   enum display_modifier mod)
	: _name(new std::string(name)), _type(type), _modifier(mod)
{
	switch (type)
	{
	case LIST:
		_list_data = boost::make_shared<boost::optional<nodes> >(nodes());
		break;
	case STRINGS:
		_strings_data = boost::make_shared<boost::optional<strings> >(strings());
		break;
	default:
		PRINT_WARNING << "[OutputTreeNode] Please use specialized constructors for types other than LIST or STRINGS!"
			<< std::endl;
		break;
	}
}

// ----------------------------------------------------------------------------

pString OutputTreeNode::to_string() const
{
	if (_type == STRING) {
		return boost::make_shared<std::string>(**_string_data);
	}

	std::stringstream ss;
	if (_modifier == HEX)
	{
		ss << std::hex << "0x" << std::uppercase << std::setfill('0');
        switch (_type)
        {
            case UINT32:
                ss << std::setw(8);
                break;
            case UINT16:
                ss << std::setw(4);
                break;
            case UINT64:
                ss << std::setw(16);
                break;
            default:
                break;
        }
	}
	else if (_modifier == DEC) {
		ss << std::dec;
	}

	switch (_type)
	{
	case UINT32:
		ss << **_uint32_data;
		break;
	case UINT16:
		ss << **_uint16_data;
		break;
	case UINT64:
		ss << **_uint64_data;
		break;
	case FLOAT:
		ss << **_float_data;
		break;
	case DOUBLE:
		ss << **_double_data;
		break;
	case THREAT_LEVEL:
		ss << **_level_data;
		break;
	case LIST:
	case STRINGS:
		PRINT_WARNING << "[OutputTreeNode] Called to_string() on a LIST or a STRINGS node!" << DEBUG_INFO << std::endl;
		break;
	default:
		PRINT_WARNING << "[OutputTreeNode] No _to_string() implementation for " << _type << "!" << std::endl;
	}
	return boost::make_shared<std::string>(ss.str());
}

// ----------------------------------------------------------------------------

plugin::LEVEL OutputTreeNode::get_level() const
{
	if (_type != THREAT_LEVEL)
	{
		PRINT_WARNING << "[OutputTreeNode] Tried to get a level, but is not a THREAT_LEVEL node!" << DEBUG_INFO << std::endl;
		return plugin::NO_OPINION;
	}

	if (!_level_data || !*_level_data)
	{
		PRINT_WARNING << "[OutputTreeNode] A THREAT_LEVEL node's data is empty!" << DEBUG_INFO << std::endl;
		return plugin::NO_OPINION;
	}

	return **_level_data;
}

// ----------------------------------------------------------------------------

shared_strings OutputTreeNode::get_strings() const
{
	if (_type != STRINGS)
	{
		PRINT_WARNING << "[OutputTreeNode] Tried to get strings, but is not a STRINGS node!" << DEBUG_INFO << std::endl;
		return shared_strings();
	}

	if (!_strings_data || !*_strings_data)
	{
		PRINT_WARNING << "[OutputTreeNode] A STRINGS node's data is empty!" << DEBUG_INFO << std::endl;
		return shared_strings();
	}

	return shared_strings(new strings(**_strings_data));
}

// ----------------------------------------------------------------------------

void OutputTreeNode::append(pNode node)
{
	if (_type != LIST)
	{
		PRINT_WARNING << "[OutputTreeNode] Tried to append a node, but is not a list of nodes!" << DEBUG_INFO << std::endl;
		return;
	}

	if (!_list_data || !*_list_data) {
		_list_data = boost::make_shared<boost::optional<nodes> >(nodes());
	}

	// The JSON formatter cannot handle identical names in a list. Rename duplicates if necessary.
	int i = 2;
	auto initial_name = *node->get_name();
	auto current_name = initial_name;
	for (auto it = (*_list_data)->begin() ; it != (*_list_data)->end() ; ++it)
	{
		if (*(*it)->get_name() == current_name)
		{
			std::stringstream ss;
			ss << initial_name << " (#" << i++ << ")";
			current_name = ss.str();
		}
	}
	if (current_name != initial_name) {
		node->set_name(current_name);
	}

	(*_list_data)->push_back(node);
}

// ----------------------------------------------------------------------------

pNodes OutputTreeNode::get_children() const
{
	if (_type != LIST)
	{
		PRINT_WARNING << "[OutputTreeNode] Tried to get the children of a non-LIST node!" << std::endl;
		return pNodes();
	}
	if (!_list_data || !*_list_data)
	{
		PRINT_WARNING << "[OutputTreeNode] A LIST node's data is empty!" << std::endl;
		return pNodes();
	}

	return boost::make_shared<nodes>(**_list_data);
}

// ----------------------------------------------------------------------------

size_t OutputTreeNode::size() const
{
	if (_type != LIST)
	{
		PRINT_WARNING << "[OutputTreeNode] Tried to get the children of a non-LIST node!" << std::endl;
		return 0;
	}
	if (!_list_data || !*_list_data)
	{
		PRINT_WARNING << "[OutputTreeNode] A LIST node's data is empty!" << std::endl;
		return 0;
	}

	return (*_list_data)->size();
}

// ----------------------------------------------------------------------------

void OutputTreeNode::clear()
{
	if (_type != LIST)
	{
		PRINT_WARNING << "[OutputTreeNode] Tried to clear a non-LIST node!" << std::endl;
		return;
	}

	if (!_list_data || !*_list_data)
	{
		PRINT_WARNING << "[OutputTreeNode] A LIST node's data is empty!" << std::endl;
		return;
	}

	(*_list_data)->clear();
}

// ----------------------------------------------------------------------------

void OutputTreeNode::update_value(const std::string& s)
{
	if (_type != STRING)
	{
		PRINT_WARNING << "[OutputTreeNode] Tried to set a string in a non-STRING node!" << std::endl;
		return;
	}
	if (!_string_data || !*_string_data)
	{
		PRINT_WARNING << "[OutputTreeNode] A STRING node's data is empty!" << std::endl;
		return;
	}

	*_string_data = boost::optional<std::string>(s);
}

// ----------------------------------------------------------------------------

void OutputTreeNode::update_value(plugin::LEVEL level)
{
	if (_type != THREAT_LEVEL)
	{
		PRINT_WARNING << "[OutputTreeNode] Tried to set a LEVEL in a non-THREAT_LEVEL node!" << std::endl;
		return;
	}
	if (!_level_data || !*_level_data)
	{
		PRINT_WARNING << "[OutputTreeNode] A LEVEL node's data is empty!" << std::endl;
		return;
	}

	*_level_data = boost::optional<plugin::LEVEL>(level);
}

// ----------------------------------------------------------------------------

shared_strings OutputTreeNode::get_strings()
{
	if (_type != STRINGS)
	{
		PRINT_WARNING << "[OutputTreeNode] Tried to get the strings of a non-STRING node!" << std::endl;
		return shared_strings();
	}
	if (!_strings_data || !*_strings_data)
	{
		PRINT_WARNING << "[OutputTreeNode] A STRINGS node's data is empty!" << std::endl;
		return shared_strings();
	}

	return shared_strings(new strings(**_strings_data));
}

// ----------------------------------------------------------------------------

void OutputTreeNode::append(const std::string& s)
{
	if (_type != STRINGS)
	{
		PRINT_WARNING << "[OutputTreeNode] Tried to append a string, but is not a list of strings!" << std::endl;
		return;
	}

	if (!_strings_data || !*_strings_data) {
		_strings_data = boost::make_shared<boost::optional<strings> >(strings());
	}
	(*_strings_data)->push_back(s);
}

// ----------------------------------------------------------------------------

void OutputTreeNode::append(const strings& strs)
{
	if (_type != STRINGS)
	{
		PRINT_WARNING << "[OutputTreeNode] Tried to append strings, but is not a list of strings!" << std::endl;
		return;
	}

	if (!_strings_data || !*_strings_data) {
		_strings_data = boost::make_shared<boost::optional<strings> >(strings(strs));
	}
	else {
		(*_strings_data)->insert((*_strings_data)->end(), strs.begin(), strs.end());
	}
}

} // !namespace io
