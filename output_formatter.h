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
#include <ostream>
#include <vector>
#include <tuple>
#include <string>
#include <set>
#include <algorithm>

#include <boost/optional.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>
#include <boost/date_time.hpp>
#include <boost/algorithm/string/trim.hpp>

#include "color.h"
#include "plugin_framework/result.h" // Necessary to hold a threat level in a node.

namespace io
{

typedef std::vector<std::string> strings;
typedef std::set<std::string> string_set;
typedef std::vector<std::pair<std::string, strings> > key_values;

/**
 *	@brief	A tree representing the data to output.
 */
class OutputTreeNode
{
public:
	typedef boost::shared_ptr<OutputTreeNode> pNode;
	typedef std::vector<pNode> nodes;

	enum node_type { LIST, UINT32, UINT16, UINT64, FLOAT, DOUBLE, STRING, STRINGS, THREAT_LEVEL };

	/**
	 *	@brief	Modifiers that control the way a node's content is displayed.
	 *
	 *	Formatters may chose to ignore some modifiers.
	 *
	 *	NONE		Nothing
	 *	DEC			Print as a decimal number (for UINT64, UINT32 and UINT16)
	 *	HEX			Print as an hexadecimal number (for UINT64, UINT32 and UINT16)
	 */
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

	OutputTreeNode(const std::string& name, float f, display_modifier mod = NONE)
		: _name(name), _type(FLOAT), _float_data(f), _modifier(mod)
	{}

	OutputTreeNode(const std::string& name, double d, display_modifier mod = NONE)
		: _name(name), _type(DOUBLE), _double_data(d), _modifier(mod)
	{}

	OutputTreeNode(const std::string& name, const std::string& s, display_modifier mod = NONE)
		: _name(name), _type(STRING), _string_data(s), _modifier(mod)
	{}

	OutputTreeNode(const std::string& name, const nodes& nodes, display_modifier mod = NONE)
		: _name(name), _type(LIST), _list_data(nodes), _modifier(mod)
	{}

	OutputTreeNode(const std::string& name, const strings& strs, display_modifier mod = NONE)
		: _name(name), _type(STRINGS), _strings_data(strs), _modifier(mod)
	{}

	OutputTreeNode(const std::string& name, const string_set strs, display_modifier mod = NONE)
		: _name(name), _type(STRINGS), _modifier(mod)
	{
		_strings_data = strings(strs.begin(), strs.end());
	}

	OutputTreeNode(const std::string& name, plugin::Result::LEVEL level, display_modifier mod = NONE)
		: _name(name), _type(THREAT_LEVEL), _level_data(level), _modifier(mod)
	{}

	// ----------------------------------------------------------------------------

	OutputTreeNode(const std::string& name, enum node_type type, enum display_modifier mod = NONE)
		: _name(name), _type(type), _modifier(mod)
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

	display_modifier get_modifier() const {
		return _modifier;
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
			case THREAT_LEVEL:
				ss << *_level_data;
				break;
			case LIST:
			case STRINGS:
				PRINT_WARNING << "[OutputFormatter] Called to_string() on a LIST or a STRINGS node!" << DEBUG_INFO << std::endl;
				break;
		}
		return ss.str();
	}

	// ----------------------------------------------------------------------------

	plugin::Result::LEVEL get_level() const 
	{
		if (_type != THREAT_LEVEL) 
		{
			PRINT_WARNING << "[OutputTreeNode] Tried to get a level, but is not a THREAT_LEVEL node!" << DEBUG_INFO << std::endl;
			return plugin::Result::NO_OPINION;
		}
		return *_level_data;
	}

	strings get_strings() const
	{
		if (_type != STRINGS)
		{
			PRINT_WARNING << "[OutputTreeNode] Tried to get strings, but is not a STRINGS node!" << DEBUG_INFO << std::endl;
			return strings();
		}
		return *_strings_data;
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
			PRINT_WARNING << "[OutputFormatter] Tried to append a node, but is not a list of nodes!" << DEBUG_INFO << std::endl;
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
	 *	@brief	Empties the contents of a LIST node.
	 */
	void clear()
	{
		if (_type != LIST)
		{
			PRINT_WARNING << "[OutputFormatter] Tried to clear a non-LIST node!" << std::endl;
			return;
		}
		_list_data->clear();
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
	boost::optional<plugin::Result::LEVEL>	_level_data;
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

	/**
	 *	@brief	Appends data to the output.
	 *
	 *	@param	pNode n The data to append.
	 *	@param	const std::string& file_path The path to the corresponding file.
	 *
	 *	The file_path parameter is used as a unique identifier for a particular analysis.
	 */
	void add_data(pNode n, const std::string& file_path)
	{
		boost::optional<pNode> file_node = _root->find_node(file_path);
		if (file_node) 
		{
			if ((*file_node)->find_node(n->get_name())) {
				PRINT_WARNING << "Multiple nodes using the name " << n->get_name() << " in a dictionary." << std::endl;
			}
			(*file_node)->append(n);
		}
		else
		{
			pNode new_file_node(new OutputTreeNode(file_path, OutputTreeNode::LIST));
			new_file_node->append(n);
			_root->append(new_file_node);
		}
	}

	// ----------------------------------------------------------------------------

	/**
	*	@brief	Find a node in a list of nodes based on its name, for a particular file.
	*
	*	The search will stop at the first occurrence of the name, so using duplicate
	*	node names is not a good idea.
	*
	*	@param	const std::string& name The name of the node to locate.
	*	@param	const std::string file_path The file whose analysis should be searched.
	*
	*	@return	A boost::optional which may contain the located node, if it was found.
	*/
	boost::optional<pNode> find_node(const std::string& name, const std::string file_path) 
	{
		boost::optional<pNode> file_node = _root->find_node(file_path);
		if (!file_node) {
			return boost::optional<pNode>();
		}
		return (*file_node)->find_node(name);
	}

	// ----------------------------------------------------------------------------

	/**
	 *	@brief	Dumps the formatted data into target output stream.
	 *
	 *	@param	std::ostream& sink	The output stream.
	 *	@param	Whether the stream ends here. Set to false if more data should be appended later on.
	 *
	 *	This last parameter was added because writing the output at the end may cause too much information
	 *	to be stored in the RAM. Using end_stream enables the caller to flush the formatter's data from time
	 *	to time.
	 */
	virtual void format(std::ostream& sink, bool end_stream = true) = 0;

protected:
	std::string _header;
	std::string _footer;
	boost::shared_ptr<OutputTreeNode> _root; // The analysis data is contained in this field
};

/**
 *	@brief	The default formatter. Displays the data as a human readable text.
 */
class RawFormatter : public OutputFormatter
{

public:
	virtual void format(std::ostream& sink, bool end_stream = true);

private:
	/**
	 *	@brief	Recursive function used to dump the contents of a tree.
	 *
	 *	@param	std::stringstream& sink The stringstream into which the data should be written.
	 *	@param	pNode node The node to dump.
	 *	@param	int max_width For LIST nodes, the size of the children's biggest name (for pretty
	 *			printing purposes).
	 *	@param	int level The hierarchical level of the node to dump (higher is deeper in the tree).
	 */
	void _dump_node(std::ostream& sink, pNode node, int max_width = 0, int level = 0);

	/**
	 *	@brief	Special printing handling for plugin output.
	 *
	 *	The plugins' output needs special code to be printed in a more readable fashion than a 
	 *	simple list of keys and values.
	 *
	 *	@param	std::stringstream& sink The stringstream into which the data should be written.
	 *	@param	pNode node The node to dump.
	 */
	void _dump_plugin_node(std::ostream& sink, pNode node);

};

/**
*	@brief	Formatter that prints the analysis result in JSON.
*/
class JsonFormatter : public OutputFormatter
{
public:
	virtual void format(std::ostream& sink, bool end_stream = true);

private:
	/**
	 *	@brief	Function which dumps the contents of a single node into JSON notation.
	 *
	 *	@param	std::ostream& sink The target output stream.
	 *	@param	pNode node The node to dump.
	 *	@param	int level The indentation level.
	 *	@param	bool append_comma Whether a comma should be appended at the end of the node contents
				(useful when dumping lists).
	 */
	void _dump_node(std::ostream& sink, pNode node, int level = 1, bool append_comma = false);
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