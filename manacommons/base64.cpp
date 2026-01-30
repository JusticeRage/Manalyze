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

#include "manacommons/base64.h"

namespace utils {

pString b64encode(const std::vector<std::uint8_t>& bytes)
{	
	if (bytes.size() == 0) {
		return std::make_shared<std::string>("");
	}

	static const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string out;
	out.reserve(((bytes.size() + 2) / 3) * 4);
	int line_len = 0;

	auto append_char = [&](char c) {
		if (line_len == 64) {
			out.push_back('\n');
			line_len = 0;
		}
		out.push_back(c);
		++line_len;
	};

	for (size_t i = 0; i < bytes.size(); i += 3)
	{
		const size_t remaining = bytes.size() - i;
		std::uint32_t triple = static_cast<std::uint32_t>(bytes[i]) << 16;
		if (remaining > 1) {
			triple |= static_cast<std::uint32_t>(bytes[i + 1]) << 8;
		}
		if (remaining > 2) {
			triple |= static_cast<std::uint32_t>(bytes[i + 2]);
		}

		append_char(kAlphabet[(triple >> 18) & 0x3F]);
		append_char(kAlphabet[(triple >> 12) & 0x3F]);
		append_char(remaining > 1 ? kAlphabet[(triple >> 6) & 0x3F] : '=');
		append_char(remaining > 2 ? kAlphabet[triple & 0x3F] : '=');
	}

	return std::make_shared<std::string>(out);
}

} // !namespace utils
