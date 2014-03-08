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

unsigned int PE::_rva_to_offset(boost::uint32_t rva)
{
	// Find the corresponding section.
	pimage_section_header section = pimage_section_header();
	for (std::vector<pimage_section_header>::const_iterator it = _section_table.begin() ; it != _section_table.end() ; ++it)
	{
		if ((*it)->VirtualAddress <= rva && rva < (*it)->VirtualAddress + (*it)->VirtualSize)
		{
			section = *it;
			break;
		}
	}
	if (section == NULL) {
		return 0; // No section matches the RVA.
	}
	return rva - section->VirtualAddress + section->PointerToRawData;
}

// ----------------------------------------------------------------------------

bool PE::_parse_directories(FILE* f)
{
	return _parse_imports(f);
}

// ----------------------------------------------------------------------------

bool PE::_parse_imports(FILE* f)
{
	if (_ioh.directories[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
	{
		std::cout << "[!] Warning: No imports." << std::endl;
		return true;
	}
	unsigned int offset = _rva_to_offset(_ioh.directories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if (!offset || fseek(f, offset, SEEK_SET))
	{
		std::cout << "[!] Error: Could not reach the import directory data (offset=0x" << std::hex << offset << ")." << std::endl;
		return false;
	}

	while (true) // We stop at the first NULL IMAGE_IMPORT_DESCRIPTOR.
	{
		pimage_import_descriptor iid(new image_import_descriptor);
		memset(iid.get(), 0, 5*sizeof(boost::uint32_t)); // Don't overwrite the last member (a string)
		iid->NameStr = std::string();
		if (20 != fread(iid.get(), 1, 20, f))
		{
			std::cout << "[!] Error: Could not read the IMAGE_IMPORT_DESCRIPTOR." << std::endl;
			return false;
		}

		// Non-standard parsing. The Name RVA is translated to an actual string here.
		unsigned int saved_offset = ftell(f);
		fseek(f, _rva_to_offset(iid->Name), SEEK_SET);
		iid->NameStr = utils::read_ascii_string(f);
		fseek(f, saved_offset, SEEK_SET);

		// Exit condition
		if (iid->OriginalFirstThunk == 0) {
			break;
		}
		pimage_library_descriptor library = pimage_library_descriptor(new image_library_descriptor(iid, std::vector<pimport_lookup_table>()));
		_imports.push_back(library);
	}

	// Parse the IMPORT_LOOKUP_TABLE for each imported library
	for (std::vector<pimage_library_descriptor>::iterator it = _imports.begin() ; it != _imports.end() ; ++it)
	{
		int ilt_offset = _rva_to_offset((*it)->first->OriginalFirstThunk);
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
				if (fseek(f, table_offset, SEEK_SET) || 2 != fread(&(import->Hint), 1, 2, f))
				{
					std::cout << "[!] Error: Could not read a HINT/NAME hint." << std::endl;
					return false;
				}
				import->Name = utils::read_ascii_string(f);

				// Go back to the import lookup table.
				fseek(f, saved_offset, SEEK_SET);
			}

			(*it)->second.push_back(import);
		}
	}

	return true;
}

// ----------------------------------------------------------------------------

void PE::dump_dos_header(std::ostream& sink) const
{
	if (!_initialized) {
		return;
	}

	sink << "DOS HEADER:" << std::endl << "-----------" << std::endl;
	sink << std::hex;
	sink << "e_magic\t\t" << _h_dos.e_magic[0] << _h_dos.e_magic[1] << std::endl;
	sink << "e_cblp\t\t" << _h_dos.e_cblp << std::endl;
	sink << "e_cp\t\t" << _h_dos.e_cp << std::endl;
	sink << "e_crlc\t\t" << _h_dos.e_crlc << std::endl;
	sink << "e_cparhdr\t" << _h_dos.e_cparhdr << std::endl;
	sink << "e_minalloc\t" << _h_dos.e_minalloc << std::endl;
	sink << "e_maxalloc\t" << _h_dos.e_maxalloc << std::endl;
	sink << "e_ss\t\t" << _h_dos.e_ss << std::endl;
	sink << "e_sp\t\t" << _h_dos.e_sp << std::endl;
	sink << "e_csum\t\t" << _h_dos.e_csum << std::endl;
	sink << "e_ip\t\t" << _h_dos.e_ip << std::endl;
	sink << "e_cs\t\t" << _h_dos.e_cs << std::endl;
	sink << "e_lfarlc\t" << _h_dos.e_lfarlc << std::endl;
	sink << "e_ovno\t\t" << _h_dos.e_ovno << std::endl;
	sink << "e_oemid\t\t" << _h_dos.e_oemid << std::endl;
	sink << "e_oeminfo\t" << _h_dos.e_oeminfo << std::endl;
	sink << "e_lfanew\t" << _h_dos.e_lfanew << std::endl <<std::endl;
}

// ----------------------------------------------------------------------------

void PE::dump_pe_header(std::ostream& sink) const
{
	if (!_initialized) {
		return;
	}

	std::vector<std::string> flags;

	sink << "PE HEADER:" << std::endl << "----------" << std::endl;
	sink << std::hex;
	sink << "Signature\t\t" << _h_pe.Signature << std::endl;
	sink << "Machine\t\t\t" << nt::translate_to_flag(_h_pe.Machine, nt::MACHINE_TYPES) << std::endl;
	sink << "NumberofSections\t" << _h_pe.NumberofSections << std::endl;
	sink << "TimeDateStamp\t\t" << _h_pe.TimeDateStamp << std::endl;
	sink << "PointerToSymbolTable\t" << _h_pe.PointerToSymbolTable << std::endl;
	sink << "NumberOfSymbols\t\t" << _h_pe.NumberOfSymbols << std::endl;
	sink << "SizeOfOptionalHeader\t" << _h_pe.SizeOfOptionalHeader << std::endl;

	sink << "Characteristics\t\t";
	flags = nt::translate_to_flags(_h_pe.Characteristics, nt::PE_CHARACTERISTICS);
	if (flags.size() > 0) 
	{
		for (std::vector<std::string>::iterator it = flags.begin() ; it != flags.end() ; ++it) 
		{
			if (it != flags.begin()) {
				sink << "\t\t\t";
			}
			sink << *it << std::endl;
		}
	}
	else {
		sink << _h_pe.Characteristics << std::endl;
	}
	sink << std::endl;
}

// ----------------------------------------------------------------------------

void PE::dump_image_optional_header(std::ostream& sink) const
{
	if (!_initialized) {
		return;
	}

	std::vector<std::string> flags;

	sink << "IMAGE OPTIONAL HEADER:" << std::endl << "----------------------" << std::endl;
	sink << std::hex;
	sink << "Magic\t\t\t\t" << nt::translate_to_flag(_ioh.Magic, nt::IMAGE_OPTIONAL_HEADER_MAGIC) << std::endl;
	sink << "LinkerVersion\t\t\t" << (int) _ioh.MajorLinkerVersion << "." << (int) _ioh.MinorLinkerVersion << std::endl;
	sink << "SizeOfCode\t\t\t" << _ioh.SizeOfCode << std::endl;
	sink << "SizeOfInitializedData\t\t" << _ioh.SizeOfInitializedData << std::endl;
	sink << "SizeOfUninitializedData\t\t" << _ioh.SizeOfUninitializedData << std::endl;
	sink << "AddressOfEntryPoint\t\t" << _ioh.AddressOfEntryPoint << std::endl;
	sink << "BaseOfCode\t\t\t" << _ioh.BaseOfCode << std::endl;

	// Field absent from PE32+ headers.
	if (_ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC["PE32"]) {
		sink << "BaseOfData\t\t\t" << _ioh.BaseOfData << std::endl;
	}

	sink << "ImageBase\t\t\t" << _ioh.ImageBase << std::endl;
	sink << "SectionAlignment\t\t" << _ioh.SectionAlignment << std::endl;
	sink << "FileAlignment\t\t\t" << _ioh.FileAlignment << std::endl;
	sink << "OperatingSystemVersion\t\t" << (int)_ioh.MajorOperatingSystemVersion << "." << (int)_ioh.MinorOperatingSystemVersion << std::endl;
	sink << "ImageVersion\t\t\t" << (int)_ioh.MajorImageVersion << "." << (int)_ioh.MinorImageVersion << std::endl;
	sink << "SubsystemVersion\t\t" << (int)_ioh.MajorSubsystemVersion << "." << (int)_ioh.MinorSubsystemVersion << std::endl;
	sink << "Win32VersionValue\t\t" << _ioh.Win32VersionValue << std::endl;
	sink << "SizeOfImage\t\t\t" << _ioh.SizeOfImage << std::endl;
	sink << "SizeOfHeaders\t\t\t" << _ioh.SizeOfHeaders << std::endl;
	sink << "Checksum\t\t\t" << _ioh.Checksum << std::endl;
	sink << "Subsystem\t\t\t" << nt::translate_to_flag(_ioh.Subsystem, nt::SUBSYSTEMS) << std::endl;
	sink << "DllCharacteristics\t\t";
	flags = nt::translate_to_flags(_ioh.DllCharacteristics, nt::DLL_CHARACTERISTICS);
	if (flags.size() > 0)
	{
		for (std::vector<std::string>::iterator it = flags.begin(); it != flags.end(); ++it)
		{
			if (it != flags.begin()) {
				sink << "\t\t\t\t";
			}
			sink << *it << std::endl;
		}
	}
	else {
		sink << _ioh.DllCharacteristics << std::endl;
	}
	sink << "SizeofStackReserve\t\t" << _ioh.SizeofStackReserve << std::endl;
	sink << "SizeofStackCommit\t\t" << _ioh.SizeofStackCommit << std::endl;
	sink << "SizeofHeapReserve\t\t" << _ioh.SizeofHeapReserve << std::endl;
	sink << "SizeofHeapCommit\t\t" << _ioh.SizeofHeapCommit << std::endl;
	sink << "LoaderFlags\t\t\t" << _ioh.LoaderFlags << std::endl;
	sink << "NumberOfRvaAndSizes\t\t" << _ioh.NumberOfRvaAndSizes << std::endl << std::endl;
}

// ----------------------------------------------------------------------------

void PE::dump_section_table(std::ostream& sink) const
{
	if (!_initialized) {
		return;
	}

	sink << "SECTION TABLE:" << std::endl << "--------------" << std::endl << std::endl;
	sink << std::hex;
	std::vector<std::string> flags;
	for (std::vector<pimage_section_header>::const_iterator it = _section_table.begin() ; it != _section_table.end() ; ++it)
	{
		sink << "Name\t\t\t" << (*it)->Name << std::endl;
		sink << "VirtualSize\t\t" << (*it)->VirtualSize << std::endl;
		sink << "VirtualAddress\t\t" << (*it)->VirtualAddress << std::endl;
		sink << "SizeOfRawData\t\t" << (*it)->SizeOfRawData << std::endl;
		sink << "PointerToRawData\t" << (*it)->PointerToRawData << std::endl;
		sink << "PointerToRelocations\t" << (*it)->PointerToRelocations << std::endl;
		sink << "PointerToLineNumbers\t" << (*it)->PointerToLineNumbers << std::endl;
		sink << "NumberOfRelocations\t" << (*it)->NumberOfRelocations << std::endl;
		sink << "NumberOfLineNumbers\t" << (*it)->NumberOfLineNumbers << std::endl;
		sink << "NumberOfRelocations\t" << (*it)->NumberOfRelocations << std::endl;
		sink << "Characteristics\t\t";
		flags = nt::translate_to_flags((*it)->Characteristics, nt::SECTION_CHARACTERISTICS);
		if (flags.size() > 0)
		{
			for (std::vector<std::string>::iterator it = flags.begin(); it != flags.end(); ++it)
			{
				if (it != flags.begin()) {
					sink << "\t\t\t";
				}
				sink << *it << std::endl;
			}
		}
		else {
			sink << _ioh.DllCharacteristics << std::endl;
		}
		sink << std::endl;
	}
}

void PE::dump_imports(std::ostream& sink) const
{
	if (!_initialized) {
		return;
	}

	sink << "IMPORTS:" << std::endl << "--------" << std::endl << std::endl;
	for (std::vector<pimage_library_descriptor>::const_iterator it = _imports.begin() ; it != _imports.end() ; ++it)
	{
		sink << (*it)->first->NameStr << std::endl;
		for ( std::vector<pimport_lookup_table>::const_iterator it2 = (*it)->second.begin() ; it2 != (*it)->second.end() ; ++it2)
		{
			if ((*it2)->Name != "") {
				sink << "\t" << (*it2)->Name << std::endl;
			}
			else {
				sink << "\tOrdinal " << ((*it2)->AddressOfData & 0x7FFF) << std::endl;
			}
		}
		sink << std::endl;
	}
	sink << std::endl;

}

} // !namespace sg
