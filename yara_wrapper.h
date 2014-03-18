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
#include <yara/yara.h>
#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>

namespace yara {

int yara_callback(int message, YR_RULE* rule, void* data);
typedef std::vector<std::pair<std::string, std::string> > matches;

class Yara
{
public:
	Yara()
	{
		_compiler = NULL;
		_rules = NULL;

		if (_instance_count == 0) {
			yr_initialize();
		}
	}

	virtual ~Yara();

	bool load_rules(const std::string& rule_filename);

	matches scan_bytes(std::vector<boost::uint8_t>& bytes);

private:
	YR_COMPILER*	_compiler;
	YR_RULES*		_rules;

	static int _instance_count;
};

typedef boost::shared_ptr<Yara> pyara;

} // !namespace yara

#endif // !_YARA_WRAPPER_H_
