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

#include "utils.h"

namespace utils {

std::string read_ascii_string(FILE* f, unsigned int max_bytes)
{
	std::string s = std::string();
	char c = 0;
	while (1 == fread(&c, 1, 1, f))
	{
		if (c == '\0') {
			break;
		}
		s += c;
		if (max_bytes != 0) // Already 0 if no limit.
		{
			--max_bytes;
			if (!max_bytes) { // <= Just in case someone thin
				break;
			}
		}
	}
	return s;
}

// ----------------------------------------------------------------------------

std::string read_unicode_string(FILE* f, unsigned int max_bytes)
{
	std::wstring s = std::wstring();
	wchar_t c = 0;
	while (2 == fread(&c, 1, 2, f))
	{
		if (c == '\0') {
			break;
		}
		s += c;
		if (max_bytes != 0) // Already 0 if no limit.
		{
			max_bytes -= 2;
			if (max_bytes <= 1) {
				break;
			}
		}
	}

	// Convert the wstring into a string
	boost::shared_array<char> conv = boost::shared_array<char>(new char[s.size() + 1]);
	memset(conv.get(), 0, sizeof(char) * (s.size() + 1));
	wcstombs(conv.get(), s.c_str(), s.size());
	return std::string(conv.get());
}

// ----------------------------------------------------------------------------

std::string read_prefixed_unicode_string(FILE* f)
{
	std::wstring s = std::wstring();
	wchar_t c = 0;
	boost::uint16_t size;
	if (2 !=fread(&size, 1, 2, f)) {
		return "";
	}

	// Microsoft's "unicode" strings are word aligned.
	for (unsigned int i = 0 ; i < size ; ++i)
	{
		if (2 != fread(&c, 1, 2, f)) {
			break;
		}
		s += c;
	}
	s += L'\0';

	// Convert the wstring into a string
	boost::shared_array<char> conv = boost::shared_array<char>(new char[s.size() + 1]);
	memset(conv.get(), 0, sizeof(char) * (s.size() + 1));
	wcstombs(conv.get(), s.c_str(), s.size());
	return std::string(conv.get());
}

// ----------------------------------------------------------------------------

bool read_string_at_offset(FILE* f, unsigned int offset, std::string& out, bool unicode)
{
	unsigned int saved_offset = ftell(f);
	if (saved_offset == -1 || fseek(f, offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach offset 0x" << std::hex << offset << "." << std::endl;
		return false;
	}
	if (!unicode) {
		out = read_ascii_string(f);
	}
	else {
		out = read_prefixed_unicode_string(f);
	}
	return !fseek(f, saved_offset, SEEK_SET) && out != "";
}

// ----------------------------------------------------------------------------

std::string uint64_to_version_number(boost::uint32_t msbytes, boost::uint32_t lsbytes)
{
	std::stringstream ss;
	ss << ((msbytes >> 16) & 0xFFFF) << "." << (msbytes & 0xFFFF) << ".";
	ss << ((lsbytes >> 16) & 0xFFFF) << "." << (lsbytes & 0xFFFF);
	return ss.str();
}

// ----------------------------------------------------------------------------

std::string timestamp_to_string(boost::uint64_t epoch_timestamp)
{
	static std::locale loc(std::cout.getloc(), new boost::posix_time::time_facet("%Y-%b-%d %H:%M:%S%F %z"));
	std::stringstream ss;
	ss.imbue(loc);
	ss << boost::posix_time::from_time_t(epoch_timestamp);
	return ss.str();
}

// ----------------------------------------------------------------------------

double DECLSPEC shannon_entropy(const std::vector<boost::uint8_t>& bytes)
{
	int frequency[256] = { 0 };
	for (std::vector<boost::uint8_t>::const_iterator it = bytes.begin() ; it != bytes.end() ; ++it)	{
		frequency[*it] += 1;
	}

	double res = 0.;
	double size = static_cast<double>(bytes.size());
	for (int i = 0 ; i < 256 ; ++i)
	{
		if (frequency[i] == 0) {
			continue;
		}
		double freq = static_cast<double>(frequency[i]) / size;
		res -= freq * log(freq) / log(2.);
	}

	return res;
}

}