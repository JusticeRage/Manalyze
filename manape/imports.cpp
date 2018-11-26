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

#include "manape/pe.h"

namespace mana {

// ----------------------------------------------------------------------------

bool PE::_parse_hint_name_table(pimport_lookup_table import) const
{
	int size_to_read = (get_architecture() == PE::x86 ? 4 : 8);

	// Read the HINT/NAME TABLE if applicable. Check the most significant byte of AddressOfData to
	// see if the import is by name or ordinal. For PE32+, AddressOfData is a uint64.
	boost::uint64_t mask = (size_to_read == 8 ? 0x8000000000000000 : 0x80000000);
	if (!(import->AddressOfData & mask))
	{
		// Import by name. Read the HINT/NAME table. For both PE32 and PE32+, its RVA is stored
		// in bits 30-0 of AddressOfData.
		unsigned int table_offset = rva_to_offset(import->AddressOfData & 0x7FFFFFFF);
		if (table_offset == 0)
		{
			PRINT_ERROR << "Could not reach the HINT/NAME table." << std::endl;
			return false;
		}

		long saved_offset = ftell(_file_handle.get());
		if (saved_offset == -1 || fseek(_file_handle.get(), table_offset, SEEK_SET) || 2 != fread(&(import->Hint), 1, 2, _file_handle.get()))
		{
			PRINT_ERROR << "Could not read a HINT/NAME hint." << std::endl;
			return false;
		}
		import->Name = utils::read_ascii_string(_file_handle.get());

		//TODO: Demangle the import name

		// Go back to the import lookup table.
		if (fseek(_file_handle.get(), saved_offset, SEEK_SET)) {
			return false;
		}
	}
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_import_lookup_table(unsigned int offset, pImportedLibrary library) const
{
	if (!offset || fseek(_file_handle.get(), offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach an IMPORT_LOOKUP_TABLE." << std::endl;
		return false;
	}

    auto imports = library->get_imports();
	while (true) // We stop at the first NULL IMPORT_LOOKUP_TABLE
	{
		pimport_lookup_table import = boost::make_shared<import_lookup_table>();
		import->AddressOfData = 0;
		import->Hint = 0;

		// The field has a size of 8 for x64 PEs
		unsigned int size_to_read = (get_architecture() == x86 ? 4 : 8);
		if (size_to_read != fread(&(import->AddressOfData), 1, size_to_read, _file_handle.get()))
		{
			PRINT_ERROR << "Could not read the IMPORT_LOOKUP_TABLE." << std::endl;
			return false;
		}

		// Exit condition
		if (import->AddressOfData == 0) {
			break;
		}

		if (!_parse_hint_name_table(import)) {
			return false;
		}

        // Verify that the number of imports is sane:
        if (imports->size() > 10000) 
        {
            PRINT_ERROR << "Gave up on parsing the import table after reading 10000 entries! This PE was almost certainly crafted manually!"
                        << DEBUG_INFO_INSIDEPE << std::endl;
            return false;
        }

        // Verify that the import is not already in the list (avoid parsing loops)
        auto found = std::find_if(imports->begin(), imports->end(), [import](const pimport_lookup_table& it)->bool
		{
		    return import->AddressOfData == it->AddressOfData &&
                   import->Hint == it->Hint &&
                   import->Name == it->Name;
		});


        if (found != imports->end()) 
        {
            PRINT_ERROR << "Read the same import twice! This PE was almost certainly crafted manually!" 
                        << DEBUG_INFO_INSIDEPE << std::endl;
            return false;
        }

		library->add_import(import);
	}
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_imports()
{
	if (!_ioh || _file_handle == nullptr) { // Image Optional Header wasn't parsed successfully.
		return false;
	}
	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_IMPORT))	{ // No imports
		return true;
	}

	while (true) // We stop at the first NULL IMAGE_IMPORT_DESCRIPTOR.
	{
		pimage_import_descriptor iid(new image_import_descriptor);
		memset(iid.get(), 0, 5*sizeof(boost::uint32_t)); // Don't overwrite the last member (a string)

		if (20 != fread(iid.get(), 1, 20, _file_handle.get()))
		{
			PRINT_ERROR << "Could not read the IMAGE_IMPORT_DESCRIPTOR." << std::endl;
			return true; // Don't give up on the rest of the parsing.
		}

		// Exit condition
		if (iid->OriginalFirstThunk == 0 && iid->FirstThunk == 0) {
			break;
		}

		// Non-standard parsing. The Name RVA is translated to an actual string here.
		auto offset = rva_to_offset(iid->Name);
		if (!offset) { // Try to use the RVA as a direct address if the imports are outside of a section.
			offset = iid->Name;
		}
		std::string library_name;
		if (!utils::read_string_at_offset(_file_handle.get(), offset, library_name))
		{
			// It seems that the Windows loader doesn't give up if such a thing happens.
			if (_imports.size() > 0)
			{
				PRINT_WARNING << "Could not read an import's name." << std::endl;
				break; // Try to continue the parsing with the available imports.
			}

			PRINT_ERROR << "Could not read an import's name." << std::endl;
			return true;
		}

		pImportedLibrary library = pImportedLibrary(new ImportedLibrary(library_name, iid));
		_imports.push_back(library);
	}

	// Parse the IMPORT_LOOKUP_TABLE for each imported library
	for (auto it = _imports.begin() ; it != _imports.end() ; ++it)
	{
		int ilt_offset;
		auto descriptor = (*it)->get_image_import_descriptor();
		if (descriptor == nullptr)
		{
			// Should never happen, standard (as opposed to delay-loaded) imports all have image import descriptors.
			PRINT_WARNING << "Tried to parse imported functions, but no image import descriptor was given!" << DEBUG_INFO_INSIDEPE << std::endl;
			continue;
		}

		if (descriptor->OriginalFirstThunk != 0) {
			ilt_offset = rva_to_offset(descriptor->OriginalFirstThunk);
		}
		else { // Some packed executables use FirstThunk and set OriginalFirstThunk to 0.
			ilt_offset = rva_to_offset(descriptor->FirstThunk);
		}

		if (!_parse_import_lookup_table(ilt_offset, *it))
		{
			// Non fatal. Stop trying to parse imports, but the ones already read will still be available.
			if ((*it)->get_name() != nullptr) {
				PRINT_WARNING << "An error occurred while trying to read functions imported by module " << *(*it)->get_name()
							  << "." << DEBUG_INFO_INSIDEPE << std::endl;
			}
			return true;
		}
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_delayed_imports()
{
    if (!_ioh || _file_handle == nullptr) { // Image Optional Header wasn't parsed successfully.
        return false;
    }
    if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT))	{ // No delayed imports
        return true;
    }

    delay_load_directory_table dldt;
	memset(&dldt, 0, 8*sizeof(boost::uint32_t));
    if (1 != fread(&dldt, 8*sizeof(boost::uint32_t), 1, _file_handle.get()))
    {
        PRINT_WARNING << "Could not read the Delay-Load Directory Table!" << std::endl;
        return true;
    }

    unsigned int offset = rva_to_offset(dldt.Name);
    if (offset == 0)
    {
        PRINT_WARNING << "Could not read the name of the DLL to be delay-loaded!" << std::endl;
        return true;
    }

	// Read the delayed DLL's name
    std::string name;
    utils::read_string_at_offset(_file_handle.get(), offset, name);
	pImportedLibrary library(new ImportedLibrary(name));

	dldt.NameStr = name;
	_delay_load_directory_table.reset(dldt);

	// Read the imports
	offset = rva_to_offset(dldt.DelayImportNameTable);

	if (_parse_import_lookup_table(offset, library)) {
		_imports.push_back(library);
	}
	return true;
}

// ----------------------------------------------------------------------------

const_shared_strings PE::get_imported_dlls() const
{
	auto destination = boost::make_shared<std::vector<std::string> >();
	if (!_initialized) {
		return destination;
	}

	for (auto it = _imports.begin() ; it != _imports.end() ; ++it)
	{
		pString s = (*it)->get_name();
		if (s != nullptr) {
			destination->push_back(*s);
		}
	}
	return destination;
}

// ----------------------------------------------------------------------------

const_shared_strings PE::get_imported_functions(const std::string& dll) const
{
	auto destination = boost::make_shared<std::vector<std::string> >();
	if (!_initialized) {
		return destination;
	}

	pImportedLibrary library = pImportedLibrary();

	// We don't want to use PE::_find_imported_dlls: no regexp matching is necessary, since we only look for a simple exact name here.
	for (auto it = _imports.begin() ; it != _imports.end() ; ++it)
	{
		pString name = (*it)->get_name();
		if (name != nullptr && *name == dll)
		{
			library = (*it);
			break;
		}
	}

	if (library != nullptr)
	{
		auto functions = library->get_imports();
		if (functions == nullptr) {
			return destination;
		}
		for (auto it = functions->begin() ; it != functions->end() ; ++it)
		{
			if ((*it)->Name != "") {
				destination->push_back((*it)->Name);
			}
			else
			{
				std::stringstream ss;
				ss << "#" << ((*it)->AddressOfData & 0x7FFF);
				destination->push_back(ss.str());
			}
		}
	}

	return destination;
}

// ----------------------------------------------------------------------------

shared_imports PE::find_imported_dlls(const std::string& name_regexp,
									  bool  case_sensitivity) const
{
	std::vector<pImportedLibrary> destination;
	if (!_initialized) {
		return boost::make_shared<const std::vector<pImportedLibrary> >(destination);
	}

	boost::regex e;
	if (case_sensitivity) {
		e = boost::regex(name_regexp);
	}
	else {
		e = boost::regex(name_regexp, boost::regex::icase);
	}

	for (auto it = _imports.begin() ; it != _imports.end() ; ++it)
	{
		pString name = (*it)->get_name();
		if (name != nullptr && boost::regex_match(*name, e)) {
			destination.push_back(*it);
		}
	}
	return boost::make_shared<const std::vector<pImportedLibrary> >(destination);
}

// ----------------------------------------------------------------------------

const_shared_strings PE::find_imports(const std::string& function_name_regexp,
									  const std::string& dll_name_regexp,
									  bool  case_sensitivity) const
{
	auto destination = boost::make_shared<std::vector<std::string> >();
	if (!_initialized) {
		return destination;
	}

	auto matching_dlls = find_imported_dlls(dll_name_regexp);

	boost::regex e;
	if (case_sensitivity) {
		e = boost::regex(function_name_regexp);
	}
	else {
		e = boost::regex(function_name_regexp, boost::regex::icase);
	}

	// Iterate on matching DLLs
	for (auto it = matching_dlls->begin() ; it != matching_dlls->end() ; ++it)
	{
		auto imported_functions = (*it)->get_imports();
		if (imported_functions == nullptr) {
			continue;
		}
		// Iterate on functions imported by each of these DLLs
		for (auto it2 = imported_functions->begin() ; it2 != imported_functions->end() ; ++it2)
		{
			std::string name;
			if ((*it2)->Name == "") 
			{
				std::stringstream ss;
				ss << "#" << ((*it2)->AddressOfData & 0x7FFF);
				name = ss.str();
			}
			else {
				name = (*it2)->Name;
			}
			// Functions may be imported multiple times, don't add the same one twice.
			if (boost::regex_match(name, e) && std::find(destination->begin(), destination->end(), name) == destination->end()) {
				destination->push_back(name);
			}
		}
	}
	return destination;
}

} // !namespace mana
