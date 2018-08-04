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
#include <set>
#include <sstream>
#include <boost/make_shared.hpp>
#include <boost/cstdint.hpp>
#include <boost/optional.hpp>

#include "color.h"
#include "plugin_framework/threat_level.h"

#if defined BOOST_WINDOWS_API && !defined DECLSPEC_MANACOMMONS
#ifdef MANALYZE_EXPORT
#define DECLSPEC_MANACOMMONS    __declspec(dllexport)
	#else
#define DECLSPEC_MANACOMMONS    __declspec(dllimport)
	#endif
#elif !defined BOOST_WINDOWS_API && !defined DECLSPEC_MANACOMMONS
	#define DECLSPEC_MANACOMMONS
#endif

namespace io
{

typedef std::vector<std::string> strings;
typedef std::shared_ptr<strings> shared_strings;
typedef std::set<std::string> string_set;
typedef boost::shared_ptr<std::string> pString;

/**
*	@brief	A tree representing the data to output.
*/
class OutputTreeNode
{
public:
	typedef boost::shared_ptr<OutputTreeNode> pNode;
	typedef std::vector<pNode> nodes;
	typedef boost::shared_ptr<nodes> pNodes;
	typedef boost::shared_ptr<boost::optional<boost::uint32_t> > shared_opt_uint32;
	typedef boost::shared_ptr<boost::optional<boost::uint16_t> > shared_opt_uint16;
	typedef boost::shared_ptr<boost::optional<boost::uint64_t> > shared_opt_uint64;
	typedef boost::shared_ptr<boost::optional<float> > shared_opt_float;
	typedef boost::shared_ptr<boost::optional<double> > shared_opt_double;
	typedef boost::shared_ptr<boost::optional<std::string> > shared_opt_string;
	typedef boost::shared_ptr<boost::optional<nodes> > shared_opt_nodes;
	typedef boost::shared_ptr<boost::optional<strings> > shared_opt_strings;
	typedef boost::shared_ptr<boost::optional<plugin::LEVEL> > shared_opt_level;

	enum node_type { LIST, UINT32, UINT16, UINT64, FLOAT, DOUBLE, STRING, STRINGS, THREAT_LEVEL };

	/**
	*	@brief	Modifiers that control the way a node's content is displayed.
	*
	*	Formatters may chose to ignore some modifiers.
	*
	*	NONE		Nothing
	*	DEC			Print as a decimal number (for UINT64, UINT32 and UINT16)
	*	HEX			Print as an hexadecimal number (for UINT64, UINT32 and UINT16)
	*	AFTER_NAME	Print as a column after the name (for STRINGS)
	*	NEW_LINE	Print as a column after a new line (for STRINGS)
	*	HIDE_NAME	Do not print the node's name (for STRING)
	*/
	enum display_modifier { NONE, DEC, HEX, AFTER_NAME, NEW_LINE, HIDE_NAME };

	// ----------------------------------------------------------------------------

	DECLSPEC_MANACOMMONS OutputTreeNode(const std::string& name, boost::uint32_t i, display_modifier mod = DEC)
		: _name(new std::string(name)), _type(UINT32), _uint32_data(new boost::optional<boost::uint32_t>(i)), _modifier(mod)
	{}

	DECLSPEC_MANACOMMONS OutputTreeNode(const std::string& name, boost::uint16_t s, display_modifier mod = DEC)
		: _name(new std::string(name)), _type(UINT16), _uint16_data(new boost::optional<boost::uint16_t>(s)), _modifier(mod)
	{}

	DECLSPEC_MANACOMMONS OutputTreeNode(const std::string& name, boost::uint64_t l, display_modifier mod = DEC)
		: _name(new std::string(name)), _type(UINT64), _uint64_data(new boost::optional<boost::uint64_t>(l)), _modifier(mod)
	{}

	DECLSPEC_MANACOMMONS OutputTreeNode(const std::string& name, float f, display_modifier mod = NONE)
		: _name(new std::string(name)), _type(FLOAT), _float_data(new boost::optional<float>(f)), _modifier(mod)
	{}

	DECLSPEC_MANACOMMONS OutputTreeNode(const std::string& name, double d, display_modifier mod = NONE)
		: _name(new std::string(name)), _type(DOUBLE), _double_data(new boost::optional<double>(d)), _modifier(mod)
	{}

	DECLSPEC_MANACOMMONS OutputTreeNode(const std::string& name, const std::string& s, display_modifier mod = NONE)
		: _name(new std::string(name)), _type(STRING), _string_data(new boost::optional<std::string>(s)), _modifier(mod)
	{}

	DECLSPEC_MANACOMMONS OutputTreeNode(const std::string& name, const nodes& n, display_modifier mod = NONE)
		: _name(new std::string(name)), _type(LIST), _list_data(new boost::optional<nodes>(n)), _modifier(mod)
	{}

	DECLSPEC_MANACOMMONS OutputTreeNode(const std::string& name, const strings& strs, display_modifier mod = NONE)
		: _name(new std::string(name)), _type(STRINGS), _strings_data(new boost::optional<strings>(strs)), _modifier(mod)
	{}

	DECLSPEC_MANACOMMONS OutputTreeNode(const std::string& name, const string_set& strs, display_modifier mod = AFTER_NAME)
		: _name(new std::string(name)), _type(STRINGS), _modifier(mod)
	{
		_strings_data = boost::make_shared<boost::optional<strings> >(strings(strs.begin(), strs.end()));
	}

	DECLSPEC_MANACOMMONS OutputTreeNode(const std::string& name, plugin::LEVEL level, display_modifier mod = NONE)
		: _name(new std::string(name)), _type(THREAT_LEVEL), _level_data(new boost::optional<plugin::LEVEL>(level)), _modifier(mod)
	{}

	// ----------------------------------------------------------------------------

	/**
	 *	@brief	This constructor is used to create a LIST or STRINGS OutputTreeNode.
	 *
	 *	@param	const std::string& name The name of the node.
	 *	@param	enum node_type type The type of the node.
	 *	@param	enum display_modifier mod = NONE A modifier to alter the way the node is printed.
	 */
	DECLSPEC_MANACOMMONS OutputTreeNode(const std::string& name, enum node_type type, enum display_modifier mod = NONE);

	// ----------------------------------------------------------------------------

	DECLSPEC_MANACOMMONS pString get_name() const {
		return _name;
	}

	// ----------------------------------------------------------------------------

	DECLSPEC_MANACOMMONS void set_name(const std::string& name) {
		_name->assign(name);
	}

	// ----------------------------------------------------------------------------

	DECLSPEC_MANACOMMONS node_type get_type() const {
		return _type;
	}

	// ----------------------------------------------------------------------------

	DECLSPEC_MANACOMMONS display_modifier get_modifier() const {
		return _modifier;
	}

	// ----------------------------------------------------------------------------

	DECLSPEC_MANACOMMONS void set_modifier(display_modifier mod) {
		_modifier = mod;
	}

	// ----------------------------------------------------------------------------

	/**
	*	@brief	Returns a string representation of the data contained by the node.
	*
	*	For instance, a UINT32 node containing 10 and the HEX modifier will be displayed as "0xA".
	*	LIST and STRINGS nodes cannot be displayed this way.
	*
	*	@return	A string representation of the contained data.
	*/
	DECLSPEC_MANACOMMONS pString to_string() const;

	// ----------------------------------------------------------------------------

	DECLSPEC_MANACOMMONS plugin::LEVEL get_level() const;

	// ----------------------------------------------------------------------------

	DECLSPEC_MANACOMMONS shared_strings get_strings() const;

	// ----------------------------------------------------------------------------

	/**
	*	@brief	Appends a node to a LIST node.
	*
	*	@param	pNode node	The list to append.
	*/
	DECLSPEC_MANACOMMONS void append(pNode node);

	// ----------------------------------------------------------------------------

	/**
	*	@brief	Returns the data contained by a LIST node (a vector of nodes).
	*/
	DECLSPEC_MANACOMMONS pNodes get_children() const;

	// ----------------------------------------------------------------------------

	/**
	 *	@brief	Returns the size of a LIST node.
	 */
	DECLSPEC_MANACOMMONS size_t size() const;

	// ----------------------------------------------------------------------------

	/**
	*	@brief	Empties the contents of a LIST node.
	*/
	DECLSPEC_MANACOMMONS void clear();

	// ----------------------------------------------------------------------------

	DECLSPEC_MANACOMMONS void update_value(const std::string& s);

	// ----------------------------------------------------------------------------

	DECLSPEC_MANACOMMONS void update_value(plugin::LEVEL level);

	// ----------------------------------------------------------------------------

	/**
	*	@brief	Returns the data contained by a STRINGS node (a vector of strings).
	*/
	DECLSPEC_MANACOMMONS shared_strings get_strings();

	// ----------------------------------------------------------------------------

	/**
	*	@brief	Appends a string to a STRINGS node.
	*
	*	@param	const std::string& s The string to append.
	*/
	DECLSPEC_MANACOMMONS void append(const std::string& s);

	// ----------------------------------------------------------------------------

	/**
	*	@brief	Appends a list of strings to a STRINGS node.
	*
	*	@param	const strings& strs The strings to append.
	*/
	DECLSPEC_MANACOMMONS void append(const strings& strs);

	// ----------------------------------------------------------------------------

	/**
	*	@brief	Find a node in a list of nodes based on its name.
	*
	*	The search will stop at the first occurrence of the name, so using duplicate
	*	node names is not a good idea.
	*
	*	@param	const std::string& name The name of the node to locate.
	*
	*	@return	A pointer which may point to the located node, or be NULL.
	*/
	DECLSPEC_MANACOMMONS pNode find_node(const std::string& name) const;

private:
	pString _name;
	enum node_type _type;

	shared_opt_uint32	_uint32_data;
	shared_opt_uint16	_uint16_data;
	shared_opt_uint64	_uint64_data;
	shared_opt_float	_float_data;
	shared_opt_double	_double_data;
	shared_opt_string	_string_data;
	shared_opt_nodes	_list_data;
	shared_opt_strings	_strings_data;
	shared_opt_level	_level_data;
	display_modifier	_modifier;		// Additional info hinting at how the data should be displayed,
										// i.e. hexadecimal or decimal for integers.

};

typedef boost::shared_ptr<OutputTreeNode> pNode;
typedef std::vector<pNode> nodes;
typedef boost::shared_ptr<nodes> pNodes;

/**
*	@brief	For LIST nodes, returns the size of the biggest child's name.
*
*	Used for pretty printing purposes with the RawFormatter.
*
*	@param	pNode node The (LIST) node to work on.
*
*	@return	The maximum size of the children's names.
*/
DECLSPEC_MANACOMMONS size_t determine_max_width(pNode node);

} // !namespace io
