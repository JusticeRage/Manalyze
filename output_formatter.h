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

#ifndef _OUTPUT_FORMATTER_H_
#define _OUTPUT_FORMATTER_H_

#include <sstream>
#include <vector>
#include <tuple>
#include <string>

#include <boost/optional.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>
#include <boost/date_time.hpp>

#include "color.h"

namespace io
{

typedef std::vector<std::string> strings;
typedef std::vector<std::pair<std::string, strings> > key_values;

/**
 *	@brief	A tree representing the data to output.
 */
class OutputTreeNode
{
public:
	typedef boost::shared_ptr<OutputTreeNode> pNode;
	typedef std::vector<pNode> nodes;

	enum node_type { LIST, UINT32, UINT16, UINT64, FLOAT, DOUBLE, STRING, STRINGS };
	enum display_modifier { NONE, DEC, HEX };

	// ----------------------------------------------------------------------------

	OutputTreeNode(const std::string& name, boost::uint32_t i, display_modifier mod = DEC)
		: _name(name), _type(UINT32), _uint32_data(i), _modifier(mod)
	{}

	OutputTreeNode(const std::string& name, boost::uint16_t s, display_modifier mod = DEC)
		: _name(name), _type(UINT16), _uint16_data(s), _modifier(mod)
	{}

	OutputTreeNode(const std::string& name, boost::uint64_t l, display_modifier mod = DEC)
		: _name(name), _type(UINT64), _uint64_data(l), _modifier(mod)
	{}

	OutputTreeNode(const std::string& name, float f)
		: _name(name), _type(FLOAT), _float_data(f), _modifier(NONE)
	{}

	OutputTreeNode(const std::string& name, double d)
		: _name(name), _type(DOUBLE), _double_data(d), _modifier(NONE)
	{}

	OutputTreeNode(const std::string& name, const std::string& s)
		: _name(name), _type(STRING), _string_data(s), _modifier(NONE)
	{}

	OutputTreeNode(const std::string& name, const nodes& nodes)
		: _name(name), _type(LIST), _list_data(nodes), _modifier(NONE)
	{}

	OutputTreeNode(const std::string& name, const strings& strs)
		: _name(name), _type(STRINGS), _strings_data(strs), _modifier(NONE)
	{}

	// ----------------------------------------------------------------------------

	OutputTreeNode(const std::string& name, enum node_type type)
		: _name(name), _type(type)
	{
		switch (type)
		{
			case LIST:
				_list_data = nodes();
				break;
			case STRINGS:
				_strings_data = strings();
				break;
		}
	}

	// ----------------------------------------------------------------------------

	std::string get_name() const {
		return _name;
	}

	// ----------------------------------------------------------------------------

	node_type get_type() const {
		return _type;
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
	std::string to_string() const 
	{
		if (_type == STRING) {
			return *_string_data;
		}

		std::stringstream ss;
		if (_modifier == HEX) {
			ss << std::hex << "0x";
		}
		else if (_modifier == DEC) {
			ss << std::dec;
		}

		switch (_type)
		{
			case UINT32:
				ss << *_uint32_data;
				break;
			case UINT16:
				ss << *_uint16_data;
				break;
			case UINT64:
				ss << *_uint64_data;
				break;
			case FLOAT:
				ss << *_float_data;
				break;
			case DOUBLE:
				ss << *_double_data;
				break;
			case LIST:
			case STRINGS:
				PRINT_WARNING << "[OutputFormatter] Called to_string() on a LIST or a STRINGS node!" << std::endl;
				break;
		}
		return ss.str();
	}

	// ----------------------------------------------------------------------------

	/**
	 *	@brief	Appends a node to a LIST node.
	 *
	 *	@param	pNode node	The list to append.
	 */
	void append(pNode node)
	{
		if (_type != LIST) 
		{
			PRINT_WARNING << "[OutputFormatter] Tried to append a node, but is not a list of nodes!" << std::endl;
			return;
		}

		if (!_list_data) {
			_list_data = nodes();
		}
		_list_data->push_back(node);
	}

	// ----------------------------------------------------------------------------

	/**
	 *	@brief	Returns the data contained by a LIST node (a vector of nodes).
	 */
	nodes get_children() 
	{
		if (_type != LIST)
		{
			PRINT_WARNING << "[OutputFormatter] Tried to get the children of a non-LIST node!" << std::endl;
			return nodes();
		}
		return *_list_data;
	}

	// ----------------------------------------------------------------------------

	/**
	 *	@brief	Returns the data contained by a STRINGS node (a vector of strings).
	 */
	strings get_strings()
	{
		if (_type != STRINGS)
		{
			PRINT_WARNING << "[OutputFormatter] Tried to get the strings of a non-STRING node!" << std::endl;
			return strings();
		}
		return *_strings_data;
	}

	// ----------------------------------------------------------------------------

	/**
	 *	@brief	Appends a string to a STRINGS node.
	 *
	 *	@param	const std::string& s The string to append.
	 */
	void append(const std::string& s)
	{
		if (_type != STRINGS) 
		{
			PRINT_WARNING << "[OutputFormatter] Tried to append a string, but is not a list of strings!" << std::endl;
			return;
		}

		if (!_strings_data) {
			_strings_data = strings();
		}
		_strings_data->push_back(s);
	}

	// ----------------------------------------------------------------------------

	/**
	*	@brief	Appends a list of strings to a STRINGS node.
	*
	*	@param	const strings& strs The strings to append.
	*/
	void append(const strings& strs)
	{
		if (_type != STRINGS)
		{
			PRINT_WARNING << "[OutputFormatter] Tried to append strings, but is not a list of strings!" << std::endl;
			return;
		}

		if (!_strings_data) {
			_strings_data = strings(strs);
		}
		else {
			_strings_data->insert(_strings_data->end(), strs.begin(), strs.end());
		}
	}

	// ----------------------------------------------------------------------------

	/**
	 *	@brief	Find a node in a list of nodes based on its name.
	 *
	 *	The search will stop at the first occurrence of the name, so using duplicate
	 *	node names is not a good idea.
	 *
	 *	@param	const std::string& name The name of the node to locate.
	 *
	 *	@return	A boost::optional which may contain the located node, if it was found.
	 */
	boost::optional<pNode> find_node(const std::string& name) const;

private:
	std::string _name;
	enum node_type _type;

	boost::optional<boost::uint32_t>		_uint32_data;
	boost::optional<boost::uint16_t>		_uint16_data;
	boost::optional<boost::uint64_t>		_uint64_data;
	boost::optional<float>					_float_data;
	boost::optional<double>					_double_data;
	boost::optional<std::string>			_string_data;
	boost::optional<nodes>					_list_data;
	boost::optional<strings>				_strings_data;
	display_modifier						_modifier;		// Additional info hinting at how the data should be displayed,
															// i.e. hexadecimal or decimal for ints.

};

typedef boost::shared_ptr<OutputTreeNode> pNode;
typedef std::vector<pNode> nodes;


/**
 *	@brief	Abstract class describing objects whose role is to display the output of the program
 *			in a specific format (raw, json, ...).
 */
class OutputFormatter
{
public:
	OutputFormatter() {
		_root = pNode(new OutputTreeNode("root", OutputTreeNode::LIST));
	}

	/**
	 *	@brief	Changes the header of the formatter.
	 *
	 *	This is the text that will be printed before the underlying data is displayed.
	 *
	 *	@param const std::string& header	The new header.
	 */
	virtual void set_header(const std::string& header) {
		_header = header;
	}

	// ----------------------------------------------------------------------------

	virtual void set_footer(const std::string& footer) {
		_footer = footer;
	}

	// ----------------------------------------------------------------------------

	void add_data(pNode n) {
		// TODO: Add a level above "category" to support multiple analyzes.
		if (_root->find_node(n->get_name())) {
			PRINT_WARNING << "Multiple nodes using the name " << n->get_name() << " in a dictionary." << std::endl;
		}
		_root->append(n);
	}

	// ----------------------------------------------------------------------------

	/**
	*	@brief	Find a node in a list of nodes based on its name.
	*
	*	The search will stop at the first occurrence of the name, so using duplicate
	*	node names is not a good idea.
	*
	*	@param	const std::string& name The name of the node to locate.
	*
	*	@return	A boost::optional which may contain the located node, if it was found.
	*/
	boost::optional<pNode> find_node(const std::string& name) {
		return _root->find_node(name);
	}

	// ----------------------------------------------------------------------------

	/**
	 *	@brief	Returns a string containing the formatted data.
	 */
	virtual std::string format() = 0;

protected:
	std::string _header;
	std::string _footer;
	boost::shared_ptr<OutputTreeNode> _root; // The analysis data is contained in this field
};

class RawFormatter : public OutputFormatter
{

public:
	virtual std::string format();

private:
	/**
	 *	@brief	(Possibly) Recursive function used to dump the contents of a tree.
	 *
	 *	@param	std::stringstream& sink The stringstream into which the data should be written.
	 *	@param	pNode node The node to dump.
	 *	@param	int max_width For LIST nodes, the size of the children's biggest name (for pretty
	 *			printing purposes).
	 *	@param	int level The hierarchical level of the node to dump (higher is deeper in the tree).
	 */
	void _dump_node(std::stringstream& sink, pNode node, int max_width = 0, int level = 0);

};

// ----------------------------------------------------------------------------

/**
 *	@brief	For LIST nodes, returns the size of the biggest child's name.
 *
 *	Used for pretty printing purposes with the RawFormatter.
 *
 *	@param	pNode node The (LIST) node to work on.
 *
 *	@return	The maximum size of the children's names.
 */
int determine_max_width(pNode node);

// ----------------------------------------------------------------------------

/**
*	@brief	Converts a uint64 into a version number structured like X.X.X.X.
*
*	@param	boost::uint32_t msbytes The most significant bytes of the version number.
*	@param	boost::uint32_t lsbytes The least significant bytes of the version number.
*
*	@return	A string containing the "translated" version number.
*/
std::string uint64_to_version_number(boost::uint32_t msbytes, boost::uint32_t lsbytes);

// ----------------------------------------------------------------------------

/**
*	@brief	Converts a POSIX timestamp into a human-readable string.
*
*	@param	uint32_t epoch_timestamp The timestamp to convert.
*
*	@return	A human readable string representing the given timestamp.
*/
std::string timestamp_to_string(boost::uint64_t epoch_timestamp);

} // !namespace sg

#endif // !_OUTPUT_FORMATTER_H_