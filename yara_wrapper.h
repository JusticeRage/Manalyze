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

#ifndef _YARA_WRAPPER_H_
#define _YARA_WRAPPER_H_

#define NOMINMAX // Yara seems to pull in some min/max stuff that messes with std::min and std::max.
#include <iostream>
#include <string>
#include <list>
#include <vector>
#include <map>
#include <yara/yara.h>
#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>

namespace yara {

/**
 *	@brief	A callback used when yara iterates through its signatures.
 *
 *	Using Yara metadata allows me to return more expressive results than simple, alphanumeric rule names.
 *
 *	@param	void* data	A pointer to a pmatch object which will be filled with the matching rules' metadata.
 */
int get_match_metadata(int message, YR_RULE* rule, void* data);

typedef std::map<std::string, std::string> match;
typedef boost::shared_ptr<std::map<std::string, std::string> > pmatch;
typedef std::vector<pmatch> matches;

class Yara
{
public:
	Yara()
	{
		_compiler = NULL;
		_rules = NULL;
		_current_rules = "";

		if (_instance_count == 0) {
			yr_initialize();
		}
	}

	virtual ~Yara();

	/**
	 *	@brief	Loads rules inside a Yara engine.
	 *
	 *	Scanning will not work before rules have been loaded.
	 *
	 *	@param	const std::string& rule_filename The file containing the rules.
	 *
	 *	@return	Whether the rules were loaded successfully.
	 */
	bool load_rules(const std::string& rule_filename);

	/**
	 *	@brief	Tries to match a given input with the currently loaded Yara rules.
	 *
	 *	@param	std::vector<boost::uint8_t>& bytes The bytes to scan.
	 *
	 *	@return	A map containing the rule's metadata for all matching signatures.
	 */
	matches scan_bytes(std::vector<boost::uint8_t>& bytes);

private:
	YR_COMPILER*	_compiler;
	YR_RULES*		_rules;

	std::string		_current_rules;

	static int _instance_count;
};

typedef boost::shared_ptr<Yara> pyara;

} // !namespace yara

#endif // !_YARA_WRAPPER_H_
