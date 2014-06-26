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

#ifndef _PE_H_
#define _PE_H_

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <string>
#include <vector>
#include <set>
#include <exception>

#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/scoped_array.hpp>
#include <boost/cstdint.hpp>
#include <boost/regex.hpp>
#include <boost/system/api_config.hpp>

#include "nt_values.h"  // Windows-related #defines flags are declared in this file.
#include "pe_structs.h" // All typedefs and structs are over there
#include "utils.h"
#include "resources.h"	// Definition of the Resource class
#include "section.h"	// Definition of the Section class
#include "color.h"		// Allows changing the font color in the terminal

#if defined BOOST_WINDOWS_API
	#ifdef SGPE_EXPORT
		#define DECLSPEC    __declspec(dllexport)
	#else
		#define DECLSPEC    __declspec(dllimport)
	#endif
#else
	#define DECLSPEC
#endif

namespace sg {

typedef boost::shared_ptr<std::vector<std::string> > shared_strings;
typedef boost::shared_ptr<const std::vector<std::string> > const_shared_strings;
typedef boost::shared_ptr<std::vector<pSection> > shared_sections;
typedef boost::shared_ptr<std::vector<pResource> > shared_resources;
typedef boost::shared_ptr<const std::vector<boost::uint8_t> > shared_bytes;
typedef boost::shared_ptr<std::string> pString;

class PE
{

public:
	DECLSPEC PE(const std::string& path);
	DECLSPEC virtual ~PE() {}
	DECLSPEC static boost::shared_ptr<PE> create(const std::string& path);

	DECLSPEC size_t get_filesize() const;

    DECLSPEC pString get_path() const { 
		return pString(new std::string(_path)); 
	}

	/**
	 *	@brief	Get the sections of the PE.
	 *
	 *	@return	A shared object containing the section information.
	 */
	DECLSPEC shared_sections get_sections() const { 
		return shared_sections(new std::vector<pSection>(_sections));
	}


	/**
	 *	@brief	Returns the list of DLLs imported by the PE.
	 *
	 *	Implementation is located in imports.cpp.
	 */
	DECLSPEC const_shared_strings get_imported_dlls() const;

	/**
	 *	@brief	Returns the list of functions imported from a specified DLL.
	 *
	 *	@param	const std::string& dll The DLL from which we want the imported functions.
	 *
	 *	@return	A shared vector in which the imported function names will be stored. Functions 
	 *			imported by ordinal will be returned as "#N",  N being the ordinal number.
	 *
	 *	Implementation is located in imports.cpp.
	 */
	DECLSPEC const_shared_strings get_imported_functions(const std::string& dll) const;

	/**
	 *	@brief	Finds imported functions matching regular expressions.
	 *
	 *	@param	const std::string& function_name_regexp		The regular expression selecting function names.
	 *	@param	const std::string& dll_name_regexp			The regular expression selecting imported dlls into which the
	 *														functions should be searched.
	 *
	 *	@return	A shared vector containing the matching function names.
	 *
	 *	The default value for dll_name_regexp implies that all DLLs should be searched.
	 *	Note that functions will only be returned if they match the WHOLE input sequence.
	 *	/!\ Warning: Functions imported by ordinal can NOT be found using this function!
	 *
	 *	Implementation is located in imports.cpp.
	 */
	DECLSPEC const_shared_strings find_imports(const std::string& function_name_regexp,
											   const std::string& dll_name_regexp = ".*") const;

	/**
	 *	@brief	Functions used to display the detailed contents of the PE.
	 *
	 *	@param	std::ostream& sink	The stream into which the information should be written.
	 *								Default is stdout.
	 *
	 *	Implementation is located in dump.cpp.
	 */
	DECLSPEC void dump_dos_header(std::ostream& sink = std::cout) const;
	DECLSPEC void dump_pe_header(std::ostream& sink = std::cout) const;
	DECLSPEC void dump_image_optional_header(std::ostream& sink = std::cout) const;
	DECLSPEC void dump_section_table(std::ostream& sink = std::cout, bool compute_hashes = false) const;
	DECLSPEC void dump_imports(std::ostream& sink = std::cout) const;
	DECLSPEC void dump_exports(std::ostream& sink = std::cout) const;
	DECLSPEC void dump_resources(std::ostream& sink = std::cout, bool compute_hashes = false) const;
	DECLSPEC void dump_version_info(std::ostream& sink = std::cout) const;
	DECLSPEC void dump_debug_info(std::ostream& sink = std::cout) const;
	DECLSPEC void dump_relocations(std::ostream& sink = std::cout) const;
	DECLSPEC void dump_tls(std::ostream& sink = std::cout) const;
	DECLSPEC void dump_certificates(std::ostream& sink = std::cout) const;
	DECLSPEC void dump_summary(std::ostream& sink = std::cout) const;
	DECLSPEC void dump_hashes(std::ostream& sink = std::cout) const;

	DECLSPEC shared_resources get_resources() const { return shared_resources(new std::vector<pResource>(_resource_table)); }

	/**
	 *	@brief	Extracts the resources of the PE and writes them to the disk.
	 *
	 *	In the general case, the resource's raw bytes are written to a file, but some resource
	 *	types can be handled more gracefully:
	 *	* RT_GROUP_ICON (and the referenced RT_ICON resources, which cannot be extracted alone)
	 *	  are saved as .ico files. (RT_GROUP_CURSORS are supported as well, but don't seem to work
	 *	  as well.)
	 *	* RT_BITMAP as .bmp files. The bitmap header is reconstructed.
	 *	* RT_MANIFEST as .xml files.
	 *
	 *	@param	const std::string& destination_folder The folder into which the resources should
	 *			be placed.
	 *
	 *	@return	Whether the extraction was successful or not.
	 *
	 *	Implementation is located in resources.cpp.
	 */
	DECLSPEC bool extract_resources(const std::string& destination_folder);

	/**
	 *	@brief	Tells whether the PE could be parsed.
	 *
	 *	@return	True if the PE was parsed successfully (i.e. is valid), false otherwise.
	 */
	DECLSPEC bool is_valid()	const {
		return _initialized;
	}

	/**
	 * TODO: Not implemented yet.
	 */
	DECLSPEC shared_bytes get_raw_section_bytes(const std::string& section_name) const;

	/**
	 *	@brief	The delete operator. "new" had to be re-implemented in order to make it private.
	 *
	 *	@param	void* p	The memory to free.
	 */
	void operator delete(void* p);

private:
	/**
	 *	@brief	The new operator, re-implemented only so it could be made private.
	 *
	 *	Users can't be allowed to allocate objects on the heap themselves. If this happens across DLL 
	 *	boundaries, the heap will get corrupted.
	 */
	void* operator new(size_t);
	void* operator new[](size_t);

	/**
	 * Reads the first bytes of the file to reconstruct the DOS header.
	 */
	bool _parse_dos_header(FILE* f);

	/**
	 * Reads the PE header of an executable.
	 * /!\ This relies on the information gathered in _parse_dos_header. Please do not call
	 *     this function first! Actually, please don't call it at all. Let the constructor 
	 *     handle the parsing.
	 */
	bool _parse_pe_header(FILE* f);

	/**
	 *	@brief	Parses the IMAGE_OPTIONAL_HEADER structure of a PE.
	 *	/!\ This relies on the information gathered in _parse_pe_header.
	 */
	bool _parse_image_optional_header(FILE* f);

	/**
	 *	@brief	Parses the IMAGE_SECTION_HEADERs of a PE.
	 *	/!\ This relies on the information gathered in _parse_pe_header.
	 */
	bool _parse_section_table(FILE* f);

	/**
	 *	@brief	Courtesy function used to parse all the PE directories (imports, exports, resources, ...).
	 *	/!\ This relies on the information gathered in _parse_image_optional_header.
	 */
	bool _parse_directories(FILE* f);

	/**
	 *	@brief	Parses the imports of a PE.
	 *	
	 *	Included in the _parse_directories call.
	 *	/!\ This relies on the information gathered in _parse_image_optional_header.
	 *
	 *	Implemented in imports.cpp
	 */
	bool _parse_imports(FILE* f);

	/**
	 *	@brief	Parses the exports of a PE.
	 *	
	 *	Included in the _parse_directories call.
	 *	/!\ This relies on the information gathered in _parse_image_optional_header.
	 */
	bool _parse_exports(FILE* f);

	/**
	 *	@brief	Parses the resources of a PE.
	 *
	 *	Included in the _parse_directories call.
	 *	/!\ This relies on the information gathered in _parse_pe_header.
	 *
	 *	Implemented in resources.cpp
	 */
	bool _parse_resources(FILE* f);

	/**
	 *	@brief	Parses the relocation table of a PE.
	 *
	 *	Included in the _parse_directories call.
	 *	/!\ This relies on the information gathered in _parse_pe_header.
	 */
	bool _parse_relocations(FILE* f);
	
	/**
	 *	@brief	Parses the Thread Local Storage callback table of a PE.
	 *
	 *	Included in the _parse_directories call.
	 *	/!\ This relies on the information gathered in _parse_pe_header.
	 */
	bool _parse_tls(FILE* f);

	/**
	 *	@brief	Parses the debug information of a PE.
	 *
	 *	Included in the _parse_directories call.
	 *	/!\ This relies on the information gathered in _parse_pe_header.
	 *
	 *	Implemented in resources.cpp
	 */
	bool _parse_debug(FILE* f);

	/**
	 *	@brief	Parses the certificate information (Authenticode) of a PE.
	 *
	 *	Included in the _parse_directories call.
	 *	/!\ This relies on the information gathered in _parse_pe_header.
	 */
	bool _parse_certificates(FILE* f);

	/**
	 *	@brief	Translates a Relative Virtual Address into an offset in the file.
	 *
	 *	@param	boost::uint32_t rva The RVA to translate
	 *
	 *	@return	The corresponding offset in the file, or 0 if the RVA could not be translated.
	 */
	unsigned int _rva_to_offset(boost::uint64_t rva) const;

	/**
	 *	@brief	Translates a Virtual Address (*not relative to the image base*) into an offset in the file.
	 *
	 *	@param	boost::uint32_t rva The VA to translate
	 *
	 *	@return	The corresponding offset in the file, or 0 if the VA could not be translated.
	 */
	unsigned int _va_to_offset(boost::uint64_t va) const;

	/**
	 *	@brief	Moves the file cursor to the target directory.
	 *
	 *	@param	FILE* f			The PE file object.
	 *	@param	int directory	The directory to reach, i.e. IMAGE_DIRECTORY_ENTRY_EXPORT.
	 *
	 *	@return	Whether the directory was successfully reached.
	 */
	bool _reach_directory(FILE* f, int directory) const;

	/**
	 *	@brief	Reads an image_resource_directory at the current position in a file.
	 *
	 *	@param	image_resource_directory& dir The structure to fill.
	 *	@param	FILE* f The file to read from.
	 *	@param	unsigned int offset The offset at which to jump before reading the directory.
	 *			The offset is relative to the beginning of the resource "section" (NOT a RVA). 
	 *			If it is 0, the function reads from the cursor's current location.
	 *
	 *	Implementation is located in resources.cpp
	 *
	 *	@return	Whether a structure was successfully read.
	 */
	bool _read_image_resource_directory(image_resource_directory& dir, FILE* f, unsigned int offset = 0);

	/**
	 *	@brief	Finds imported DLLs whose names match a particular regular expression.
	 *
	 *	@param	const std::string& name_regexp The regular expression used to match DLL names.
	 *	@param	std::vector<pimage_library_descriptor>& destination The vector into which the result should be stored.
	 *
	 *	Implementation is located in imports.cpp.
	 */
	std::vector<pimage_library_descriptor> _find_imported_dlls(const std::string& name_regexp) const;

	std::string							_path;
    bool								_initialized;

	/* 
	    -----------------------------------
	    Fields related to the PE structure.
	    -----------------------------------
	    Those fields that are extremely close to the PE format and offer little abstraction.
	*/
	dos_header								_h_dos;
	pe_header								_h_pe;
	image_optional_header					_ioh;
	std::vector<pSection>					_sections;
	std::vector<pimage_library_descriptor>	_imports;
	image_export_directory					_ied;
	std::vector<pexported_function>			_exports;
	std::vector<pResource>					_resource_table;
	std::vector<pdebug_directory_entry>		_debug_entries;
	std::vector<pimage_base_relocation>		_relocations;
	image_tls_directory						_tls;
	std::vector<pwin_certificate>			_certificates;
};


} /* !namespace sg */

#endif /* !_PE_H_ */
