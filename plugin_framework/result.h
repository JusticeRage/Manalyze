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

#ifndef _RESULT_H_
#define _RESULT_H_

#include <vector>
#include <string>
#include <sstream>
#include <boost/shared_ptr.hpp>
#include <boost/optional.hpp>

#include "threat_level.h" // Contains the LEVEL enum.
#include "output_tree_node.h"

namespace plugin
{


typedef boost::shared_ptr<std::string> pString;
typedef boost::shared_ptr<std::vector<std::string> > pInformation;

/**
 *	@brief	Represents the result of a PE analysis, as returned by plugins.
 *
 *	It is composed of three parts: a threat level which indicates how dangerous the
 *	PE is according to the plugin, a summary describing the findings and some text 
 *	information giving more details.
 */
class Result
{
	friend class IPlugin; // Result's constructor should only be called from IPlugin::make_result().

public:
	void set_level(LEVEL level) 
	{ 
		io::pNode opt_level = _data->find_node("level");
		if (!opt_level) // Should never happen.
		{
			PRINT_WARNING << "[Result] A result object has no level node. This should be investigated." 
				<< DEBUG_INFO << std::endl;
			_data->append(io::pNode(new io::OutputTreeNode("level", level)));
		}
		else {
			opt_level->update_value(level);
		}
	}

	/**
	 *	@brief	This function is simply a setter which only sets the value if the new one is higher than
	 *			the former.
	 *
	 *	@param	LEVEL level	The level to set.
	 */
	void raise_level(LEVEL level)
	{ 
		io::pNode opt_level = _data->find_node("level");
		if (!opt_level) // Should never happen.
		{
			PRINT_WARNING << "[Result] A result object has no level node. This should be investigated." 
				<< DEBUG_INFO << std::endl;
			_data->append(io::pNode(new io::OutputTreeNode("level", level)));
		}
		else
		{
			if (level > opt_level->get_level()) {
				opt_level->update_value(level);
			}
		}
	}

	LEVEL get_level() const
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
	
	void set_summary(const std::string& s) 
	{ 
		io::pNode opt_summary = _data->find_node("summary");
		if (!opt_summary) {
			_data->append(io::pNode(new io::OutputTreeNode("summary", s)));
		}
		else {
			opt_summary->update_value(s);
		}
	}

	pString get_summary() const 
	{ 
		io::pNode opt_summary = _data->find_node("summary");
		if (!opt_summary) {
			return pString();
		}
		else {
			return opt_summary->to_string();
		}
	}

	/**
	 *	@brief	Add any kind of information to a result. This should primarily be used with strings, but
	 *			some plugins may need to return more complex information.
	 *
	 *	@param	T t The object to add to the result output.
	 */
	template<class T>
	void add_information(T t) 
	{
		io::pNode output = get_information();
		output->append(io::pNode(new io::OutputTreeNode(_create_node_name(), t)));
	}

	/**
	 *	@brief	Template specialization for nodes.
	 */
	template<>
	void add_information(io::pNode node)
	{
		io::pNode output = get_information();
		output->append(node);
	}

	/**
	*	@brief	Add any kind of information to a result. This should primarily be used with strings, but
	*			some plugins may need to return more complex information.
	*
	*	Contrary to the previous function, this one allows the user to give a name to the node. This is useful
	*	to display STRINGS and LIST nodes properly.
	*
	*	@param	const std::string& name The name to give to the node.
	*	@param	T t The object to add to the result output.
	*/
	template<class T>
	void add_information(const std::string& name, T t)
	{
		io::pNode output = get_information();
		output->append(io::pNode(new io::OutputTreeNode(name, t)));
	}

	io::pNode get_output() const { return _data; }

	/**
	 *	@brief	Returns the node of the result's data containing the plugin's "free" output.
	 *
	 *	@returns	A pointer to a node which is never NULL. The node may be empty however.
	 */
	io::pNode get_information() const 
	{
		io::pNode output = _data->find_node("plugin_output");
		if (!output)
		{
			PRINT_WARNING << "[Result] A result object's output data wasn't initialized!" 
				<< DEBUG_INFO << std::endl;
			output = io::pNode(new io::OutputTreeNode("plugin_output", io::OutputTreeNode::LIST));
			_data->append(output);
		}
		return output;
	}

private:
	Result(const std::string& plugin_name)
	{
		_data = io::pNode(new io::OutputTreeNode(plugin_name, io::OutputTreeNode::LIST));
		_data->append(io::pNode(new io::OutputTreeNode("level", NO_OPINION)));
		_data->append(io::pNode(new io::OutputTreeNode("plugin_output", io::OutputTreeNode::LIST)));
	}

	/**
	 *	@brief	Creates an node name to use when information is appended to _data.
	 *
	 *	The name of the node is simply an index, because we do not intend to print it in most cases.
	 */
	std::string _create_node_name()
	{		
		std::stringstream ss;
		if (_data->get_children()) {
			ss << _data->get_children()->size();
		}
		else {
			ss << 0;
		}
		return ss.str();
	}

	io::pNode _data;
};
typedef boost::shared_ptr<Result> pResult;

} // !namespace plugin

#endif // !_RESULT_H_