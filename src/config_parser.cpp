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

#include <algorithm>
#include <cctype>

config parse_config(const std::string& config_file)
{
	std::ifstream input(config_file.c_str());
	config conf;

	if (!input.is_open())
	{
		PRINT_WARNING << "Could not read configuration file (" << config_file << ")." << std::endl;
		return conf;
	}

	auto ltrim = [](std::string& s) {
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char c) { return !std::isspace(c); }));
	};
	auto rtrim = [](std::string& s) {
		s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char c) { return !std::isspace(c); }).base(), s.end());
	};
	auto trim = [&](std::string& s) {
		ltrim(s);
		rtrim(s);
	};

	std::string line;
	while (std::getline(input, line))
	{
		std::string plugin_name, plugin_attribute, attribute_value;

		trim(line);
		if (line.empty() || line[0] == '#') {
			continue;
		}

		auto eq_pos = line.find('=');
		if (eq_pos == std::string::npos) {
			PRINT_WARNING << "Could not parse \"" << line << "\" in " << config_file << "." << std::endl;
			continue;
		}

		std::string left = line.substr(0, eq_pos);
		std::string right = line.substr(eq_pos + 1);
		trim(left);
		trim(right);

		auto dot_pos = left.find('.');
		if (dot_pos == std::string::npos) {
			PRINT_WARNING << "Could not parse \"" << line << "\" in " << config_file << "." << std::endl;
			continue;
		}

		plugin_name = left.substr(0, dot_pos);
		plugin_attribute = left.substr(dot_pos + 1);
		trim(plugin_name);
		trim(plugin_attribute);

		if (plugin_name.empty() || plugin_attribute.empty() || right.empty()) {
			PRINT_WARNING << "Could not parse \"" << line << "\" in " << config_file << "." << std::endl;
			continue;
		}

		conf[plugin_name][plugin_attribute] = right;
	}
	input.close();
	return conf;
}
