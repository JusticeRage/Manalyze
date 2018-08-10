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
#include <boost/algorithm/string/trim.hpp>

#include "manacommons/output_tree_node.h"
#include "manacommons/escape.h" // String escaping functions
#include "manacommons/color.h"
#include "plugin_framework/result.h" // Necessary to hold a threat level in a node.

namespace io
{

// ----------------------------------------------------------------------------
// Base class of all the formatters
// ----------------------------------------------------------------------------

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

	virtual ~OutputFormatter() {}

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
		pNode file_node = _root->find_node(file_path);
		if (file_node)
		{
			if (file_node->find_node(*n->get_name())) {
				PRINT_WARNING << "Multiple nodes using the name " << *n->get_name() << " in a dictionary." << std::endl;
			}
			file_node->append(n);
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
	pNode find_node(const std::string& name, const std::string& file_path)
	{
		pNode file_node = _root->find_node(file_path);
		if (!file_node) {
			return pNode();
		}
		return file_node->find_node(name);
	}

	// ----------------------------------------------------------------------------

	/**
	 *	@brief	Dumps the formatted data into target output stream.
	 *
	 *	@param	std::ostream& sink	The output stream.
	 *	@param	Whether the stream ends here. Set to false if more data will be appended later on.
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

// ----------------------------------------------------------------------------

/**
 *	@brief	The default formatter. Displays the data as a human readable text.
 */
class RawFormatter : public OutputFormatter
{

public:
	void format(std::ostream& sink, bool end_stream = true) override;
	typedef escaped_string_raw<sink_type> escape_grammar;

private:
	/**
	 *	@brief	Recursive function used to dump the contents of a tree.
	 *
	 *	@param	std::stringstream& sink The stringstream into which the data should be written.
	 *	@param	pNode node The node to dump.
	 *	@param	int max_width The size of the children's biggest name of the parent node (for pretty
	 *			printing purposes).
	 *	@param	int level The hierarchical level of the node to dump (higher is deeper in the tree).
	 */
	void _dump_node(std::ostream& sink, pNode node, size_t max_width = 0, int level = 0);

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

	/**
	*	@brief	Display function specific to STRINGS node.
	*
	*	@param	std::stringstream& sink The stringstream into which the data should be written.
	*	@param	pNode node The node to dump.
	*	@param	int max_width The size of the children's biggest name of the parent node (for pretty
	*			printing purposes).
	*	@param	int level The hierarchical level of the node to dump (higher is deeper in the tree).
	*/
	void _dump_strings_node(std::ostream& sink, pNode node, size_t max_width = 0, int level = 0);

};

// ----------------------------------------------------------------------------

/**
*	@brief	Formatter that prints the analysis result in JSON.
*/
class JsonFormatter : public OutputFormatter
{
public:
	virtual void format(std::ostream& sink, bool end_stream = true);
	typedef escaped_string_json<sink_type> escape_grammar;

private:
	/**
	 *	@brief	Function which dumps the contents of a single node into JSON notation.
	 *
	 *	@param	std::ostream& sink The target output stream.
	 *	@param	pNode node The node to dump.
	 *	@param	int level The indentation level.
	 *	@param	bool append_comma Whether a comma should be appended at the end of the node contents
				(useful when dumping lists).
	 *	@param	bool print_name Whether the name of the node should be displayed (useful when printing
	 *			inside JSON lists).
	 */
	void _dump_node(std::ostream& sink, pNode node, int level = 1, bool append_comma = false, bool print_name = true);
};

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

} // !namespace io
