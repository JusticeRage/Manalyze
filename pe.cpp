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

#include "pe.h"

namespace sg {

PE::PE(const std::string& path)
	: _path(path), _initialized(false), _size(-1)
{
	FILE* f = fopen(_path.c_str(), "rb");
	if (f == NULL) 
	{
		std::cout << "[!] Error: Could not open " << _path << std::endl;
		goto END;
	}
	if (!_parse_dos_header(f)) {
		goto END;
	}

	if (!_parse_pe_header(f)) {
		goto END;
	}

	if (!_parse_image_optional_header(f)) {
		goto END;
	}

	if (!_parse_section_table(f)) {
		goto END;
	}

	if (!_parse_directories(f)) {
		goto END;
	}	

	_initialized = true;

	END:
	if (f != NULL) {
		fclose(f);
	}
}

// ----------------------------------------------------------------------------

size_t PE::get_filesize()
{
    if (_size != -1) {
        return _size;
    }

	FILE* f = fopen(_path.c_str(), "rb");
	size_t res = 0;
	if (f == NULL) {
		return res;
	}
	fseek(f, 0, SEEK_END);
	res = ftell(f);
	fclose(f);
    _size = res;
	return _size;
}

// ----------------------------------------------------------------------------

bool PE::_parse_dos_header(FILE* f)
{
	memset(&_h_dos, 0, sizeof(_h_dos));
    if (sizeof(_h_dos) > get_filesize())
	{
		std::cout << "[!] Error: Input file is too small to be a valid PE." << std::endl;
		return false;
	}

	if (sizeof(_h_dos) != fread(&_h_dos, 1, sizeof(_h_dos), f))
	{
		std::cout << "[!] Error: Could not read the DOS Header." << std::endl;
		return false;
	}
	if (_h_dos.e_magic[0] != 'M' || _h_dos.e_magic[1] != 'Z')
	{
		std::cout << "[!] Error: DOS Header is invalid." << std::endl;
		return false;
	}
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_pe_header(FILE* f)
{
	memset(&_h_pe, 0, sizeof(_h_pe));
	if (fseek(f, _h_dos.e_lfanew, SEEK_SET))
	{
		std::cout << "[!] Error: Could not reach PE header (fseek to offset " <<  _h_dos.e_lfanew << " failed)." << std::endl;
		return false;
	}
	if (sizeof(_h_pe) != fread(&_h_pe, 1, sizeof(_h_pe), f))
	{
		std::cout << "[!] Error: Could not read the PE Header." << std::endl;
		return false;
	}
	if (_h_pe.Signature[0] != 'P' || _h_pe.Signature[1] != 'E' || _h_pe.Signature[2] != '\x00' || _h_pe.Signature[3] != '\x00')
	{
		std::cout << "[!] Error: PE Header is invalid." << std::endl;
		return false;
	}
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_image_optional_header(FILE* f)
{
	memset(&_ioh, 0, sizeof(_ioh));

	if (_h_pe.SizeOfOptionalHeader == 0)
	{
		std::cout << "[!] Warning: This PE has no Image Optional Header!." << std::endl;
		return true;
	}

	if (fseek(f, _h_dos.e_lfanew + sizeof(pe_header), SEEK_SET))
	{
		std::cout << "[!] Error: Could not reach the Image Optional Header (fseek to offset " 
			<<  _h_dos.e_lfanew + sizeof(pe_header) << " failed)." << std::endl;
		return false;
	}

	// Only read the first 0x18 bytes: after that, we have to fill the fields manually.
	if (0x18 != fread(&_ioh, 1, 0x18, f))
	{
		std::cout << "[!] Error: Could not read the Image Optional Header." << std::endl;
		return false;
	}

	if (_ioh.Magic != nt::IMAGE_OPTIONAL_HEADER_MAGIC["PE32"] && _ioh.Magic != nt::IMAGE_OPTIONAL_HEADER_MAGIC["PE32+"])
	{
		std::cout << "[!] Error: Invalid Image Optional Header magic." << std::endl;
		return false;
	}
	else if (_ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC["PE32"])
	{
		if (4 != fread(&_ioh.BaseOfData, 1, 4, f) || 4 != fread(&_ioh.ImageBase, 1, 4, f)) 
		{
			std::cout << "[!] Error: Error reading the P32 specific part of ImageOptionalHeader." << std::endl;
			return false;
		}
	}
	else
	{
		// PE32+: BaseOfData doesn't exist, and ImageBase is a uint64.
		if (8 != fread(&_ioh.ImageBase, 1, 8, f))
		{
			std::cout << "[!] Error: Error reading the P32+ specific part of ImageOptionalHeader." << std::endl;
			return false;
		}
	}

	// After this, PE32 and PE32+ structures are in sync for a while.
	if (0x28 != fread(&_ioh.SectionAlignment, 1, 0x28, f))
	{
		std::cout << "[!] Error: Error reading the common part of ImageOptionalHeader." << std::endl;
		return false;
	}

	// The next 4 values may be uint32s or uint64s depending on whether this is a PE32+ header.
	// We store them in uint64s in any case.
	if (_ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC["PE32+"])
	{
		if (40 != fread(&_ioh.SizeofStackReserve, 1, 40, f))
		{
			std::cout << "[!] Error: Error reading SizeOfStackReserve for a PE32+ IMAGE OPTIONAL HEADER." << std::endl;
			return false;
		}
	}
	else
	{
		fread(&_ioh.SizeofStackReserve, 1, 4, f);
		fread(&_ioh.SizeofStackCommit, 1, 4, f);
		fread(&_ioh.SizeofHeapReserve, 1, 4, f);
		fread(&_ioh.SizeofHeapCommit, 1, 4, f);
		fread(&_ioh.LoaderFlags, 1, 4, f);
		fread(&_ioh.NumberOfRvaAndSizes, 1, 4, f);
		if (feof(f) || ferror(f))
		{
			std::cout << "[!] Error: Error reading SizeOfStackReserve for a PE32 IMAGE OPTIONAL HEADER." << std::endl;
			return false;
		}
	}

	// The Windows Loader disregards the value if it is greater than 0x10. This trick is supposedly used to crash parsers.
	// Source: http://opcode0x90.wordpress.com/2007/04/22/windows-loader-does-it-differently/
	// TODO: Move to an analysis module, since this denotes a suspicious intent.
	if (_ioh.NumberOfRvaAndSizes > 0x10) {
		std::cout << "[!] Warning: NumberOfRvaAndSizes > 0x10. This PE may have manually been crafted." << std::endl;
	}

	for (unsigned int i = 0 ; i < std::min(_ioh.NumberOfRvaAndSizes, (boost::uint32_t) 0x10) ; ++i)
	{
		if (8 != fread(&_ioh.directories[i], 1, 8, f))
		{
			std::cout << "[!] Error: Could not read directory entry " << i << "." << std::endl;
			return false;
		}
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_section_table(FILE* f)
{
	if (fseek(f, _h_dos.e_lfanew + sizeof(pe_header) + _h_pe.SizeOfOptionalHeader, SEEK_SET))
	{
		std::cout << "[!] Error: Could not reach the Section Table (fseek to offset " 
			<<  _h_dos.e_lfanew + sizeof(pe_header) + _h_pe.SizeOfOptionalHeader << " failed)." << std::endl;
		return false;
	}

	for (int i = 0 ; i < _h_pe.NumberofSections ; ++i)
	{
		pimage_section_header sec(new image_section_header);
		memset(sec.get(), 0, sizeof(image_section_header));
		if (sizeof(image_section_header) != fread(&*sec, 1, sizeof(image_section_header), f))
		{
			std::cout << "[!] Error: Could not read section " << i << "." << std::endl;
			return false;
		}
		_section_table.push_back(sec);
	}

	return true;
}

// ----------------------------------------------------------------------------

unsigned int PE::_rva_to_offset(boost::uint32_t rva) const
{
	// Find the corresponding section.
	pimage_section_header section = pimage_section_header();
	for (std::vector<pimage_section_header>::const_iterator it = _section_table.begin() ; it != _section_table.end() ; ++it)
	{
		if (utils::is_address_in_section(rva, *it))
		{
			section = *it;
			break;
		}
	}

	if (section == NULL) 
	{
		// No section found. Maybe the VirsualSize is erroneous? Try with the RawSizeOfData.
		for (std::vector<pimage_section_header>::const_iterator it = _section_table.begin() ; it != _section_table.end() ; ++it)
		{
			if (utils::is_address_in_section(rva, *it, true))
			{
				section = *it;
				break;
			}
		}

		return 0; // No section matches the RVA.
	}
	return rva - section->VirtualAddress + section->PointerToRawData;
}

// ----------------------------------------------------------------------------

bool PE::_reach_directory(FILE* f, int directory) const
{
	if (directory > 0x10) { // There can be no more than 0x16 directories.
		return false;
	}

	if (_ioh.directories[directory].Size == 0)
	{
		return false; // Requested directory is empty.
	}
	unsigned int offset = _rva_to_offset(_ioh.directories[directory].VirtualAddress);
	if (!offset || fseek(f, offset, SEEK_SET))
	{
		std::cout << "[!] Error: Could not reach the requested directory (offset=0x" << std::hex << offset << ")." << std::endl;
		return false;
	}
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_directories(FILE* f)
{
	return _parse_imports(f) && _parse_exports(f) && _parse_resources(f);
}

// ----------------------------------------------------------------------------

bool PE::_parse_imports(FILE* f)
{
	if (!_reach_directory(f, IMAGE_DIRECTORY_ENTRY_IMPORT))	{ // No imports
		return true;
	}

	while (true) // We stop at the first NULL IMAGE_IMPORT_DESCRIPTOR.
	{
		pimage_import_descriptor iid(new image_import_descriptor);
		memset(iid.get(), 0, 5*sizeof(boost::uint32_t)); // Don't overwrite the last member (a string)

		if (20 != fread(iid.get(), 1, 20, f))
		{
			std::cout << "[!] Error: Could not read the IMAGE_IMPORT_DESCRIPTOR." << std::endl;
			return false;
		}

		// Exit condition
		if (iid->OriginalFirstThunk == 0 && iid->FirstThunk == 0) {
			break;
		}

		// Non-standard parsing. The Name RVA is translated to an actual string here.
		unsigned int offset = _rva_to_offset(iid->Name);
		if (!offset || !utils::read_string_at_offset(f, offset, iid->NameStr))
		{
			std::cout << "[!] Error: Could not read the import name." << std::endl;
			return false;
		}

		pimage_library_descriptor library = pimage_library_descriptor(new image_library_descriptor(iid, std::vector<pimport_lookup_table>()));
		_imports.push_back(library);
	}

	// Parse the IMPORT_LOOKUP_TABLE for each imported library
	for (std::vector<pimage_library_descriptor>::iterator it = _imports.begin() ; it != _imports.end() ; ++it)
	{
		int ilt_offset;
		if ((*it)->first->OriginalFirstThunk != 0) {
			ilt_offset = _rva_to_offset((*it)->first->OriginalFirstThunk);
		}
		else { // Some packed executables use FirstThunk and set OriginalFirstThunk to 0.
			ilt_offset = _rva_to_offset((*it)->first->FirstThunk);
		}
		if (!ilt_offset || fseek(f, ilt_offset, SEEK_SET))
		{
			std::cout << "[!] Error: Could not reach an IMPORT_LOOKUP_TABLE." << std::endl;
			return false;
		}

		while (true) // We stop at the first NULL IMPORT_LOOKUP_TABLE
		{
			pimport_lookup_table import = pimport_lookup_table(new import_lookup_table);
			import->AddressOfData = 0;
			import->Hint = 0;

			// The field has a size of 8 for x64 PEs
			int size_to_read = (_ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC["PE32+"] ? 8 : 4);
			if (size_to_read != fread(&(import->AddressOfData), 1, size_to_read, f))
			{
				std::cout << "[!] Error: Could not read the IMPORT_LOOKUP_TABLE." << std::endl;
				return false;
			}

			// Exit condition
			if (import->AddressOfData == 0) {
				break;
			}

			// Read the HINT/NAME TABLE if applicable. Check the most significant byte of AddressOfData to
			// see if the import is by name or ordinal. For PE32+, AddressOfData is a uint64.
			boost::uint64_t mask = (size_to_read == 8 ? 0x8000000000000000 : 0x80000000);
			if (!(import->AddressOfData & mask))
			{
				// Import by name. Read the HINT/NAME table. For both PE32 and PE32+, its RVA is stored
				// in bits 30-0 of AddressOfData.
				unsigned int table_offset = _rva_to_offset(import->AddressOfData & 0x7FFFFFFF);
				if (table_offset == 0)
				{
					std::cout << "[!] Error: Could not reach the HINT/NAME table." << std::endl;
					return false;
				}

				unsigned int saved_offset = ftell(f);
				if (saved_offset == -1 || fseek(f, table_offset, SEEK_SET) || 2 != fread(&(import->Hint), 1, 2, f))
				{
					std::cout << "[!] Error: Could not read a HINT/NAME hint." << std::endl;
					return false;
				}
				import->Name = utils::read_ascii_string(f);

				//TODO: Demangle the import name

				// Go back to the import lookup table.
				if (fseek(f, saved_offset, SEEK_SET)) {
					return false;
				}
			}

			(*it)->second.push_back(import);
		}
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_exports(FILE* f)
{
	// Don't overwrite the std::string at the end of the structure.
	unsigned int ied_size = 9*sizeof(boost::uint32_t) + 2*sizeof(boost::uint16_t);
	memset(&_ied, 0, ied_size);

	if (!_reach_directory(f, IMAGE_DIRECTORY_ENTRY_EXPORT))	{
		return true; // No exports
	}

	if (ied_size != fread(&_ied, 1, ied_size, f))
	{
		std::cout << "[!] Error: Could not read the IMAGE_EXPORT_DIRECTORY." << std::endl;
		return false;
	}

	// Read the export name
	unsigned int offset = _rva_to_offset(_ied.Name);
	if (!offset || !utils::read_string_at_offset(f, offset, _ied.NameStr))
	{
		std::cout << "[!] Error: Could not read the exported DLL name." << std::endl;
		return false;
	}
	
	// Get the address and ordinal of each exported function
	offset = _rva_to_offset(_ied.AddressOfFunctions);
	if (!offset || fseek(f, offset, SEEK_SET))
	{
		std::cout << "[!] Error: Could not reach exported functions address table." << std::endl;
		return false;
	}

	for (unsigned int i = 0 ; i < _ied.NumberOfFunctions ; ++i)
	{
		pexported_function ex = pexported_function(new exported_function);
		if (4 != fread(&(ex->Address), 1, 4, f))
		{
			std::cout << "[!] Error: Could not read an exported function's address." << std::endl;
			return false;
		}
		ex->Ordinal = _ied.Base + i;

		// If the address is located in the export directory, then it is a forwarded export.
		image_data_directory export_dir = _ioh.directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (ex->Address > export_dir.VirtualAddress && ex->Address < export_dir.VirtualAddress + export_dir.Size)
		{
			offset = _rva_to_offset(ex->Address);
			if (!offset || !utils::read_string_at_offset(f, offset, ex->ForwardName))
			{
				std::cout << "[!] Error: Could not read a forwarded export name." << std::endl;
				return false;
			}
		}

		_exports.push_back(ex);
	}

	// Associate possible exported names with the RVAs we just obtained. First, read the name and ordinal table.
	boost::scoped_array<boost::uint32_t> names(new boost::uint32_t[_ied.NumberOfNames]);
	boost::scoped_array<boost::uint16_t> ords(new boost::uint16_t[_ied.NumberOfNames]);
	offset = _rva_to_offset(_ied.AddressOfNames);
	if (!offset || fseek(f, offset, SEEK_SET))
	{
		std::cout << "[!] Error: Could not reach exported function's name table." << std::endl;
		return false;
	}

	if (_ied.NumberOfNames * sizeof(boost::uint32_t) != fread(names.get(), 1, _ied.NumberOfNames * sizeof(boost::uint32_t), f))
	{
		std::cout << "[!] Error: Could not read an exported function's name address." << std::endl;
		return false;
	}

	offset = _rva_to_offset(_ied.AddressOfNameOrdinals);
	if (!offset || fseek(f, offset, SEEK_SET))
	{
		std::cout << "[!] Error: Could not reach exported functions NameOrdinals table." << std::endl;
		return false;
	}
	if (_ied.NumberOfNames * sizeof(boost::uint16_t) != fread(ords.get(), 1, _ied.NumberOfNames * sizeof(boost::uint16_t), f))
	{
		std::cout << "[!] Error: Could not read an exported function's name ordinal." << std::endl;
		return false;
	}

	// Now match the names with with the exported addresses.
	for (unsigned int i = 0 ; i < _ied.NumberOfNames ; ++i)
	{
		offset = _rva_to_offset(names[i]);
		if (!offset || ords[i] > _exports.size() || !utils::read_string_at_offset(f, offset, _exports.at(ords[i])->Name))
		{
			std::cout << "[!] Error: Could not match an export name with its address!" << std::endl;
			return false;
		}
	}

	return true;
}

} // !namespace sg
