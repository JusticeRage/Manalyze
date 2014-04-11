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

#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <iostream>
#include <string.h>

#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>
#include <boost/date_time.hpp>

#include "hashes.h"

#include "pe_structs.h"

namespace utils 
{

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

/**
 *	@brief	Reads a unicode string prefixed by its length in a file.
 *
 *	/!\ The file cursor will be updated accordingly!
 *
 *	@param	FILE* f The file from which to read. The read will occur at the cursor's current position!
 *
 *	@return	The string at the current location in the file, converted to ASCII.
 */
std::string read_prefixed_unicode_string(FILE* f);

/**
 *	@brief	Reads a (double-)null-terminated unicode string.
 *
 *	/!\ The file cursor will be updated accordingly!
 *
 *	@param	FILE* f The file from which to read. The read will occur at the cursor's current position!
 *	@param	int max_bytes The maximum number of bytes to read from the file. 0 means no limit.
 *			If this parameter is odd, it will be rounded to max_bytes-1 since bytes are read two by two.
 *
 *	@return	The string at the current location in the file, converted to ASCII.
 */
std::string read_unicode_string(FILE* f, unsigned int max_bytes = 0);

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

/**
 *	@brief	Checks whether the address belongs to a section.
 *
 *	@param	unsigned int rva The address (RVA) to check.
 *	@param	pimage_section_header section The section in which the address may belong.
 *	@param	bool check_raw_size Use the SizeOfRawData instead of VirtualSize to determine the bounds of the section.
 *
 *	@return	Whether the RVA is between the bounds of the section.
 */
bool is_address_in_section(boost::uint64_t rva, sg::pimage_section_header section, bool check_raw_size = false);

/**
 *	@brief	Finds the section containing a given RVA.
 *
 *	@param	unsigned int rva The address whose section we want to identify.
 *	@param	const std::vector<pimage_section_header>& section_list A list of all the sections of the PE.
 *
 *	@return	A pointer to the section containing the input address. NULL if no sections match.
 */
sg::pimage_section_header find_section(unsigned int rva, const std::vector<sg::pimage_section_header>& section_list);

/**
 *	@brief	Converts a uint64 into a version number structured like X.X.X.X.
 *
 *	@param	boost::uint32_t msbytes The most significant bytes of the version number.
 *	@param	boost::uint32_t lsbytes The least significant bytes of the version number.
 *
 *	@return	A string containing the "translated" version number.
 */
std::string uint64_to_version_number(boost::uint32_t msbytes, boost::uint32_t lsbytes);

/**
 *	@brief	Converts a POSIX timestamp into a human-readable string.
 *
 *	@param	uint32_t epoch_timestamp The timestamp to convert.
 *
 *	@return	A human readable string representing the given timestamp.
 */
std::string timestamp_to_string(boost::uint32_t epoch_timestamp);

}

#endif