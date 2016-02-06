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

#include "manacommons/escape.h"

namespace io
{
	
pString escape(const std::string& s) {
	return _do_escape<escaped_string_raw<sink_type> >(s);
}

}