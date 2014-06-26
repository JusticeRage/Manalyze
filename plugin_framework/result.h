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

#ifndef _RESULT_H_
#define _RESULT_H_

#include <vector>
#include <string>
#include <boost/shared_ptr.hpp>

namespace plugin
{


typedef boost::shared_ptr<std::string> pString;
typedef boost::shared_ptr<std::vector<std::string> > pInformation;

/**
 *	@brief	Represents the result of a PE analysis, as returned by plugins.
 *
 *	It is composed of three parts: a threat level which indicates how dangerous the
 *	PE is according to the plugin, a summary describing the findings and some text 
 *	information giving more details.
 */
class Result
{

public:
	enum LEVEL { SAFE, NO_OPINION, SUSPICIOUS, MALICIOUS };

	Result() : _level(NO_OPINION),
			   _data(new std::vector<std::string>())
	{}

	void set_level(LEVEL level) { _level = level; }
	void raise_level(LEVEL level) { if (level > _level) _level = level; }
	LEVEL get_level() const		 { return _level;  }
	void set_summary(const std::string& s) { _summary = pString(new std::string(s)); }
	pString get_summary() const { return _summary; }

	void  add_information(const std::string& info) {
		_data->push_back(info);
	}
	pInformation get_information() const { return _data; }

private:
	LEVEL _level;
	pString _summary;
	pInformation _data;
};
typedef boost::shared_ptr<Result> pResult;

} // !namespace plugin

#endif // !_RESULT_H_