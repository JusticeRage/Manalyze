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

#include "config_parser.h"

config parse_config(const std::string& config_file)
{
	std::ifstream input(config_file.c_str());
	config conf;

	if (!input.is_open())
	{
		PRINT_WARNING << "Could not read configuration file (" << config_file << ")." << std::endl;
		return conf;
	}

	std::string line;
	while (std::getline(input, line))
	{
		std::string plugin_name, plugin_attribute, attribute_value;

		if (line.empty() ||
			qi::parse(line.begin(),
					  line.end(),
					  (qi::char_('#') >> +qi::char_) | +boost::spirit::ascii::space)) // Line starting with '#' or made of spaces
		{
			continue;
		}
		else if (
			qi::phrase_parse(
				line.begin(),
				line.end(),
				(+~qi::char_('.') >> '.' >> +~qi::char_('=') >> '=' >> +qi::char_),
				boost::spirit::ascii::space,
				plugin_name, plugin_attribute, attribute_value))
		{
			conf[plugin_name][plugin_attribute] = attribute_value;
		}
		else
		{
			PRINT_WARNING << "Could not parse \"" << line << "\" in " << config_file << "." << std::endl;
		}
	}
	input.close();
	return conf;
}
