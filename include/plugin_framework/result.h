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

#pragma once

#include <vector>
#include <string>
#include <sstream>
#include <boost/make_shared.hpp>
#include <boost/optional.hpp>

#include "threat_level.h" // Contains the LEVEL enum.
#include "manacommons/output_tree_node.h"

namespace plugin
{


typedef boost::shared_ptr<std::string> pString;

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
	DECLSPEC_MANACOMMONS void set_level(LEVEL level);

	/**
	 *	@brief	This function is simply a setter which only sets the value if the new one is higher than
	 *			the former.
	 *
	 *	@param	LEVEL level	The level to set.
	 */
	DECLSPEC_MANACOMMONS void raise_level(LEVEL level);

	DECLSPEC_MANACOMMONS LEVEL get_level() const;

	DECLSPEC_MANACOMMONS void set_summary(const std::string& s);

	DECLSPEC_MANACOMMONS pString get_summary() const;

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
		output->append(boost::make_shared<io::OutputTreeNode>(_create_node_name(), t, io::OutputTreeNode::HIDE_NAME));
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
		output->append(boost::make_shared<io::OutputTreeNode>(name, t));
	}

	io::pNode get_output() const { return _data; }

	/**
	 *	@brief	Returns the node of the result's data containing the plugin's "free" output.
	 *
	 *	@returns	A pointer to a node which is never NULL. The node may be empty however.
	 */
	DECLSPEC_MANACOMMONS io::pNode get_information() const;

	/**
	 * @brief	Combines the information of target result with this one.
	 * @param res	The result containing the information to merge.
	 */
	DECLSPEC_MANACOMMONS void merge(const Result& res);

private:
	// Constructor is made private, so only IPlugin::make_result() calls it.
	DECLSPEC_MANACOMMONS Result(const std::string& plugin_name);

	/**
	 *	@brief	Creates an node name to use when information is appended to _data.
	 *
	 *	The name of the node is simply an index, because we do not intend to print it in most cases.
	 */
	DECLSPEC_MANACOMMONS std::string _create_node_name() const;

	io::pNode _data;
};
typedef boost::shared_ptr<Result> pResult;

/**
*	@brief	Template specialization for io::pNodes.
*/
template<>
DECLSPEC_MANACOMMONS void Result::add_information(io::pNode node);

} // !namespace plugin
