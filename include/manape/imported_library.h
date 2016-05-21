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

#include <vector>
#include <string>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>

#include "manape/pe_structs.h"

#if defined BOOST_WINDOWS_API && !defined DECLSPEC
	#ifdef MANAPE_EXPORT
		#define DECLSPEC    __declspec(dllexport)
	#else
		#define DECLSPEC    __declspec(dllimport)
	#endif
#elif !defined BOOST_WINDOWS_API && !defined DECLSPEC
	#define DECLSPEC
#endif

namespace mana 
{

typedef boost::shared_ptr<std::string> pString;
typedef boost::shared_ptr<std::vector<pimport_lookup_table> > pImports;

/**
 *	@brief	This class represents a dynamic library (DLL) imported by the PE.
 *
 *	In the past, we used to manipulate raw structures identical to the ones defined in 
 *	the PE specification. The need to support delay-loaded libraries, which are declared 
 *  in a totally different way, lead to the creation of this more generic object.
 *	This way, all imports can be queried through the same API calls. This makes sense
 *	because most users won't care how a DLL is loaded, they'll want to know whether
 *	a particular function is imported or not.
 */
class ImportedLibrary
{
public:
	enum LOAD_TYPE { STANDARD, DELAY_LOADED };
	virtual ~ImportedLibrary() {}
	ImportedLibrary(const std::string& library_name, pimage_import_descriptor image_import_descriptor);

	/**
	 *	@brief	This constructor is used for delay-loaded libraries which do not have an 
	 *			IMAGE_IMPORT_DESCRIPTOR structure.
	 */
	ImportedLibrary(const std::string& library_name);

	DECLSPEC LOAD_TYPE get_type()	const { return _load_type; }
	DECLSPEC pString   get_name()	const { return boost::make_shared<std::string>(_library_name); }
	DECLSPEC pImports  get_imports() const { return _imported_functions; }

	/**
	 *	@brief	Returns the underlying IMAGE_IMPORT_DESCRIPTOR structure.
	 *
	 *	The structure doesn't exist for delay-loaded DLLs (< 0.1% of the cases), so if
	 *	you need to access it, make sure that get_type() == STANDARD!
	 *
	 *	@return	A pointer to the corresponding IMAGE_IMPORT_DESCRIPTOR, or nullptr for 
	 *			delay-loaded DLLs.
	 */
	DECLSPEC pimage_import_descriptor get_image_import_descriptor() const { return _image_import_descriptor; }

	void add_import(pimport_lookup_table import) { _imported_functions->push_back(import); }
	
private:
	pimage_import_descriptor			_image_import_descriptor;
	std::vector<pimport_lookup_table>	_lookup_table;
	LOAD_TYPE							_load_type;
	std::string							_library_name;
	pImports							_imported_functions;
};

typedef boost::shared_ptr<ImportedLibrary> pImportedLibrary;
	
} // !namespace mana