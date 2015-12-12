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

#ifndef  _NT_VALUES_H_
# define _NT_VALUES_H_

#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <boost/assign.hpp>
#include <boost/system/api_config.hpp>
#include <boost/shared_ptr.hpp>

#if defined BOOST_WINDOWS_API && !defined DECLSPEC
	#ifdef MANAPE_EXPORT
		#define DECLSPEC    __declspec(dllexport)
	#else
		#define DECLSPEC    __declspec(dllimport)
	#endif
#elif !defined BOOST_WINDOWS_API && !defined DECLSPEC
	#define DECLSPEC
#endif

typedef boost::shared_ptr<std::vector<std::string> > shared_strings;
typedef boost::shared_ptr<const std::vector<std::string> > const_shared_strings;
typedef boost::shared_ptr<std::string> pString;

// Directory Entries - copied from WinNT.h
// There is no need for a map for this one: we won't have to translate the values back to their names.
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

namespace nt {

typedef std::map<std::string, int> flag_dict;

// Exported flag translation maps. Definition in nt_values.cpp.
extern const DECLSPEC flag_dict PE_CHARACTERISTICS;
extern const DECLSPEC flag_dict MACHINE_TYPES;
extern const DECLSPEC flag_dict IMAGE_OPTIONAL_HEADER_MAGIC;
extern const DECLSPEC flag_dict SUBSYSTEMS;
extern const DECLSPEC flag_dict DLL_CHARACTERISTICS;
extern const DECLSPEC flag_dict SECTION_CHARACTERISTICS;
extern const DECLSPEC flag_dict RESOURCE_TYPES;
extern const DECLSPEC flag_dict LANG_IDS;
extern const DECLSPEC flag_dict CODEPAGES;
extern const DECLSPEC flag_dict FIXEDFILEINFO_FILEFLAGS;
extern const DECLSPEC flag_dict FIXEDFILEINFO_FILEOS;
extern const DECLSPEC flag_dict FIXEDFILEINFO_FILETYPE;
extern const DECLSPEC flag_dict FIXEDFILEINFO_FILESUBTYPE_DRV;
extern const DECLSPEC flag_dict FIXEDFILEINFO_FILESUBTYPE_FONT;
extern const DECLSPEC flag_dict DEBUG_TYPES;
extern const DECLSPEC flag_dict BASE_RELOCATION_TYPES;
extern const DECLSPEC flag_dict WIN_CERTIFICATE_REVISIONS;
extern const DECLSPEC flag_dict WIN_CERTIFICATE_TYPES;

/**
 *	@brief	Breaks down an integer given as input as a combination of flags.
 *
 *	@param	int value The integer to translate
 *	@param	flag_dict& dict A map containing the list of available flags and corresponding
 *			integer values.
 *
 *	@return	A list of matching flags.
 */
DECLSPEC const_shared_strings translate_to_flags(int value, const flag_dict& dict);

/**
 *	@brief	Looks up the flag corresponding to a given value, if any.
 *
 *	@param	int value The integer to translate
 *	@param	flag_dict& dict A map containing the list of available flags and corresponding
 *			integer values.
 *
 *	@return	The corresponding flag, or "UNKNOWN" if no match is found.
 */
DECLSPEC pString translate_to_flag(int value, const flag_dict& dict);

} // !namespace nt

#endif
