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

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <iostream>
#include <string.h>
#include <math.h>
#include <vector>

#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>
#include <boost/make_shared.hpp>
#include <boost/system/api_config.hpp>
#include <boost/date_time.hpp>

#include <manacommons/utf8/utf8.h> // Used to convert windows UTF-16 strings into UTF-8

#include "manape/color.h"

// Some miscellaneous functions are exported
#if defined BOOST_WINDOWS_API
	#ifdef MANAPE_EXPORT
		#define DECLSPEC    __declspec(dllexport)
	#else
		#define DECLSPEC    __declspec(dllimport)
	#endif
#else
	#define DECLSPEC
#endif

namespace btime = boost::posix_time;

namespace utils
{

typedef boost::shared_ptr<std::string> pString;
typedef boost::shared_ptr<btime::ptime> pptime;

// Disable the "unary minus operator applied to unsigned type" warning.
#pragma warning(push)
#pragma warning(disable : 4146)
/**
 *	@brief	Performs a ROL operation on a 32 bit integer.
 *	
 *	@param	x The integer to operate on.
 *	@param	n How much to rotate.
 *	
 *	@return x ROL n
 */
inline boost::uint32_t rol32(boost::uint32_t x, boost::uint32_t n)
{
	n = n % 32;
	return (x << n) | (x >> (-n & 31));
}
#pragma warning(pop)

/**
 *	@brief	Reads a null-terminated ASCII string in a file.
 *
 *	/!\ The file cursor will be updated accordingly!
 *
 *	@param	FILE* f The file from which to read. The read will occur at the cursor's current position!
 *	@param	int max_bytes The maximum number of bytes to read from the file. 0 means no limit.
 *
 *	@return	The ASCII string at the current location in the file.
 */
std::string read_ascii_string(FILE* f, unsigned int max_bytes = 0);

// ----------------------------------------------------------------------------

/**
 *	@brief	Reads a unicode string prefixed by its length in a file.
 *
 *	/!\ The file cursor will be updated accordingly!
 *
 *	@param	FILE* f The file from which to read. The read will occur at the cursor's current position!
 *
 *	@return	The string at the current location in the file, encoded as UTF-8.
 */
std::string read_prefixed_unicode_string(FILE* f);

// ----------------------------------------------------------------------------

/**
 *	@brief	Reads a unicode string prefixed by its length in a file.
 *
 *	/!\ The file cursor will be updated accordingly!
 *
 *	@param	FILE* f The file from which to read. The read will occur at the cursor's current position!
 *
 *	@return	The string at the current location in the file.
 */
std::wstring read_prefixed_unicode_wstring(FILE* f);

// ----------------------------------------------------------------------------

/**
 *	@brief	Reads a (double-)null-terminated unicode string.
 *
 *	/!\ The file cursor will be updated accordingly!
 *
 *	@param	FILE* f The file from which to read. The read will occur at the cursor's current position!
 *	@param	int max_bytes The maximum number of bytes to read from the file. 0 means no limit.
 *			If this parameter is odd, it will be rounded to max_bytes-1 since bytes are read two by two.
 *
 *	@return	The string at the current location in the file, encoded as UTF-8.
 */
std::string read_unicode_string(FILE* f, unsigned int max_bytes = 0);

// ----------------------------------------------------------------------------

/**
 *	@brief	Reads a null-terminated ASCII string in a file at a given offset.
 *
 *	This function will preserve the file cursor.
 *
 *	@param	FILE* f The file from which to read.
 *	@param	unsigned int offset	The location in the file to read.
 *	@param	std::string& out The string into which the result should be saved
 *	@param	bool unicode Set to true if the string is unicode (well, Windows' definition of
 *			unicode anyway). Default is false.
 *
 *	@return	Whether a string was successfully read.
 */
bool read_string_at_offset(FILE* f, unsigned int offset, std::string& out, bool unicode = false);

// ----------------------------------------------------------------------------

/**
 *	@brief	Calculates the entropy of a byte stream.
 *
 *	See http://en.wikipedia.org/wiki/Entropy_(information_theory)
 *
 *	@param	const std::vector<boost::uint8_t>& bytes The byte stream to work on.
 *
 *	@return	The entropy of the byte stream.
 */
double DECLSPEC shannon_entropy(const std::vector<boost::uint8_t>& bytes);

// ----------------------------------------------------------------------------

/**
 *	@brief	Converts a POSIX timestamp into a human-readable string.
 *
 *	@param	uint32_t epoch_timestamp The timestamp to convert.
 *
 *	@return	A human readable string representing the given timestamp.
 */
pString DECLSPEC timestamp_to_string(boost::uint64_t epoch_timestamp);

// ----------------------------------------------------------------------------

/**
 *	@brief	Converts a DosDate timestamp into a boost::time object.
 *
 *	@param	uint32_t dosdate The timestamp to convert.
 *
 *	@return	A shared boost ptime object representing the given timestamp.
 */
pptime DECLSPEC dosdate_to_btime(boost::uint32_t dosdate);

// ----------------------------------------------------------------------------

/**
 *	@brief	Converts a DosDate timestamp into a human-readable string.
 *
 *	@param	uint32_t dosdate The timestamp to convert.
 *
 *	@return	A human readable string representing the given timestamp.
 */
pString DECLSPEC dosdate_to_string(boost::uint32_t dosdate);

// ----------------------------------------------------------------------------
/**
 *  @brief  This helper function compares a dosdate and the PE timestamp to
 *          check whether the dosdate is actually a posix timestamp.
 *          
 *  @param  dosdate The dosdate to test.
 *  @param  pe_timestamp The reference posix time (typically, the PE compilation
 *          date from the PE header.
 *  @param  threshold How close the two timestamps should be to determine that
 *          the dosdate is actually a posix timestamp (default is 0.1%).
 */
bool DECLSPEC is_actually_posix(boost::uint32_t dosdate, boost::uint32_t pe_timestamp, float threshold = 0.001);
}
