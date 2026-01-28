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

#include "manape/utils.h"

#include <chrono>
#include <ctime>
#include <iomanip>

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

	try
	{
		std::vector<std::uint8_t> utf8result;
		utf8::utf16to8(s.begin(), s.end(), std::back_inserter(utf8result));
		return std::string(utf8result.begin(), utf8result.end());
	}
	catch (utf8::invalid_utf16&) {
		PRINT_WARNING << "Couldn't convert a string from a RT_STRING resource to UTF-8!" 
					  << DEBUG_INFO << std::endl;
	}
	return "";
}

// ----------------------------------------------------------------------------

std::wstring read_prefixed_unicode_wstring(FILE* f)
{
	std::wstring s = std::wstring();
	wchar_t c = 0;
	std::uint16_t size;
	if (2 != fread(&size, 1, 2, f)) {
		return L"";
	}

	for (unsigned int i = 0 ; i < size ; ++i)
	{
		if (2 != fread(&c, 1, 2, f)) {
			break;
		}
		s += c;
	}
	return s;
}

// ----------------------------------------------------------------------------

std::string read_prefixed_unicode_string(FILE* f)
{
	std::wstring s = read_prefixed_unicode_wstring(f);

	try
	{
		std::vector<std::uint8_t> utf8result;
		utf8::utf16to8(s.begin(), s.end(), std::back_inserter(utf8result));
		return std::string(utf8result.begin(), utf8result.end());
	}
	catch (utf8::invalid_utf16&) {
		PRINT_WARNING << "Couldn't convert a string from a RT_STRING resource to UTF-8!" 
					  << DEBUG_INFO << std::endl;
	}
	return "";
}

// ----------------------------------------------------------------------------

bool read_string_at_offset(FILE* f, unsigned int offset, std::string& out, bool unicode)
{
	auto saved_offset = ftell(f);
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
	return !fseek(f, saved_offset, SEEK_SET) && !out.empty();
}

// ----------------------------------------------------------------------------

double DECLSPEC shannon_entropy(const std::vector<std::uint8_t>& bytes)
{
	int frequency[256] = { 0 };
	for (const auto& it : bytes)	{
		frequency[it] += 1;
	}

	double res = 0.;
	auto size = static_cast<double>(bytes.size());
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

// ----------------------------------------------------------------------------

namespace {

std::tm to_utc_tm(std::time_t t)
{
	std::tm tm{};
#ifdef _WIN32
	gmtime_s(&tm, &t);
#else
	gmtime_r(&t, &tm);
#endif
	return tm;
}

std::string format_utc_time(std::time_t t)
{
	std::tm tm = to_utc_tm(t);
	std::ostringstream ss;
	ss << std::put_time(&tm, "%Y-%b-%d %H:%M:%S");
	return ss.str();
}

std::time_t timegm_utc(std::tm* tm)
{
#ifdef _WIN32
	return _mkgmtime(tm);
#else
	return timegm(tm);
#endif
}

} // namespace

pString timestamp_to_string(std::uint64_t epoch_timestamp)
{
	const std::time_t t = static_cast<std::time_t>(epoch_timestamp);
	return std::make_shared<std::string>(format_utc_time(t));
}

// ----------------------------------------------------------------------------

pptime dosdate_to_btime(std::uint32_t dosdate)
{
    if (dosdate == 0) {
        std::tm tm{};
        tm.tm_year = 1980 - 1900;
        tm.tm_mon = 0;
        tm.tm_mday = 1;
        tm.tm_hour = 0;
        tm.tm_min = 0;
        tm.tm_sec = 0;
        tm.tm_isdst = 0;
        const std::time_t t = timegm_utc(&tm);
        return std::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::from_time_t(t));
    }

    std::uint16_t date = dosdate >> 16;
    std::uint16_t time = dosdate & 0xFFFF;
    std::uint16_t year = ((date & 0xFE00) >> 9) + 1980;
    std::uint16_t month = (date & 0x1E0) >> 5;
    std::uint16_t day = date & 0x1F;
    std::uint16_t hour = (time & 0xF800) >> 11;
    std::uint16_t minute = (time & 0x7E0) >> 5;
    std::uint16_t second = (time & 0x1F) << 1;
    if (second == 60) {
        second = 59;
    }

    const bool invalid_date = month == 0 || month > 12 || day == 0 || day > 31;
    const bool invalid_time = hour > 23 || minute > 59 || second > 59;
    if (invalid_date || invalid_time) {
        PRINT_WARNING << "Tried to convert an invalid DosDate: " << dosdate << ". Falling back to posix timestamp." << DEBUG_INFO << std::endl;
        // Some samples seem to be using a standard epoch timestamp (i.e. be7dc7c927caa47740c369daf35fc5e5). Try falling back to that.
        const std::time_t t = static_cast<std::time_t>(dosdate);
        return std::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::from_time_t(t));
    }

    std::tm tm{};
    tm.tm_year = static_cast<int>(year) - 1900;
    tm.tm_mon = static_cast<int>(month) - 1;
    tm.tm_mday = static_cast<int>(day);
    tm.tm_hour = static_cast<int>(hour);
    tm.tm_min = static_cast<int>(minute);
    tm.tm_sec = static_cast<int>(second);
    tm.tm_isdst = 0;
    const std::time_t t = timegm_utc(&tm);
    return std::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::from_time_t(t));
}

// ----------------------------------------------------------------------------

bool is_actually_posix(std::uint32_t dosdate, std::uint32_t pe_timestamp, float threshold)
{
    if (dosdate == 0) {
        return false;
    }
    float variation;
    if (dosdate > pe_timestamp) {
        variation = static_cast<float>(dosdate - pe_timestamp) / static_cast<float>(dosdate);
    }
    else {
        variation = static_cast<float>(pe_timestamp - dosdate) / static_cast<float>(dosdate);
    }
    
    return fabs(variation) <= threshold;
}

// ----------------------------------------------------------------------------

pString dosdate_to_string(std::uint32_t dosdate)
{
    const auto time = dosdate_to_btime(dosdate);
    if (!time) {
        return std::make_shared<std::string>(format_utc_time(0) + " (ERROR)");
    }
    const std::time_t t = std::chrono::system_clock::to_time_t(*time);
    return std::make_shared<std::string>(format_utc_time(t));
}

// ----------------------------------------------------------------------------

} // namespace utils
