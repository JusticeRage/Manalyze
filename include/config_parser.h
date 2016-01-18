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

#include <string>
#include <map>
#include <fstream>
#include <boost/spirit/include/qi.hpp>

#include "manacommons/color.h"

namespace qi = boost::spirit::qi;

typedef std::map<std::string, std::map<std::string, std::string> > config;

/**
 *	@brief	Parses a configuration file.
 *
 *	The config file is expected to have a structure similar to this:
 *	plugin_A.attribute1 = value1
 *	plugin_A.attribute2 = value2
 *	# Comments
 *	plugin_B.attribute = value3
 *	...
 *
 *	This function returns the following map:
 *	config["plugin_A"]["attribute1"] = value1
 *	config["plugin_A"]["attribute2"] = value2
 *	config["plugin_B"]["attribute3"] = value3
 *
 *	@param	The path of the configuration file to parse.
 *
 *	@return	The parsed data.
 */
config parse_config(const std::string& config_file);
