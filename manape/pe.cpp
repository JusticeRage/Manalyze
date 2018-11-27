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

PE::PE(const std::string& path)
	: _path(path), _initialized(false)
{
	FILE* f = fopen(_path.c_str(), "rb");
	if (f == nullptr)
	{
		PRINT_ERROR << "Could not open " << _path << "." << std::endl;
		return;
	}
	_file_handle = boost::shared_ptr<FILE>(f, fclose);

	// Get the file size
	fseek(_file_handle.get(), 0, SEEK_END);
	_file_size = ftell(_file_handle.get());
	fseek(_file_handle.get(), 0, SEEK_SET);

	if (!_parse_dos_header()) {
		return;
	}

	if (!_parse_pe_header()) {
		return;
	}

	if (!_parse_image_optional_header()) {
		return;
	}

	if (!_parse_section_table()) {
		return;
	}

	// Failure is acceptable from here on.
	_initialized = true;
	_parse_coff_symbols();
	_parse_directories();
}


// ----------------------------------------------------------------------------

boost::shared_ptr<PE> PE::create(const std::string& path) {
	return boost::make_shared<PE>(path);
}

// ----------------------------------------------------------------------------

void* PE::operator new(size_t size)
{
	void* p = malloc(size);
	if (p == nullptr)
		throw std::bad_alloc();
	return p;
}

// ----------------------------------------------------------------------------

void PE::operator delete(void* p) {
	free(p);
}


// ----------------------------------------------------------------------------

boost::uint64_t PE::get_filesize() const {
	return _file_size;
}

// ----------------------------------------------------------------------------

PE::PE_ARCHITECTURE PE::get_architecture() const {
	return (_ioh->Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+") ? PE::x64 : PE::x86);
}

// ----------------------------------------------------------------------------

shared_bytes PE::get_raw_bytes(size_t size) const
{
	if(_file_handle == nullptr) {
		return nullptr;
	}
	fseek(_file_handle.get(), 0, SEEK_SET);
	if (size > _file_size) {
		size = static_cast<size_t>(_file_size);
	}
	auto res = boost::make_shared<std::vector<boost::uint8_t> >(size);
	fread(&(*res)[0], 1, size , _file_handle.get());
	return res;
}

// ----------------------------------------------------------------------------

shared_bytes PE::get_overlay_bytes(size_t size) const
{
    if (_file_handle == nullptr || !_ioh || size == 0) {
        return nullptr;
    }

    const auto sections = get_sections();
    if (!sections) {
        return nullptr;
    }

    // Find where the overlay data would be located.
    boost::uint64_t max_offset = 0;

    // If the binary is signed, look after the authenticode signature.
    if (_ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress) 
    {
        max_offset = _ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress + 
            _ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
    }
    else // Otherwise, look after the last section.
    {
        for (const auto& it : *sections)
        {
            if (it->get_pointer_to_raw_data() + it->get_size_of_raw_data() > max_offset) {
                max_offset = it->get_pointer_to_raw_data() + it->get_size_of_raw_data();
            }
        }
    }

    // The PE has no overlay data.
    if (max_offset >= get_filesize()) {
        return nullptr;
    }

    fseek(_file_handle.get(), max_offset, SEEK_SET);
    if (size > _file_size - max_offset) {
        size = static_cast<size_t>(_file_size - max_offset);
    }
    auto res = boost::make_shared<std::vector<boost::uint8_t> >(size);
    fread(&(*res)[0], 1, size, _file_handle.get());
    return res;
}

// ----------------------------------------------------------------------------

bool PE::_parse_dos_header()
{
	if (_file_handle == nullptr) {
		return false;
	}

	dos_header dos;
	memset(&dos, 0, sizeof(dos));
	if (sizeof(dos) > get_filesize())
	{
		PRINT_ERROR << "Input file is too small to be a valid PE." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (sizeof(dos) != fread(&dos, 1, sizeof(dos), _file_handle.get()))
	{
		PRINT_ERROR << "Could not read the DOS Header." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	if (dos.e_magic[0] != 'M' || dos.e_magic[1] != 'Z')
	{
		PRINT_ERROR << "DOS Header is invalid (wrong magic)." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	_h_dos.reset(dos);
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_pe_header()
{
	if (!_h_dos || _file_handle == nullptr) {
		return false;
	}

	pe_header peh;
	memset(&peh, 0, sizeof(peh));

	if (fseek(_file_handle.get(), _h_dos->e_lfanew, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach PE header (fseek to offset " <<  _h_dos->e_lfanew << " failed)."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	if (sizeof(peh) != fread(&peh, 1, sizeof(peh), _file_handle.get()))
	{
		PRINT_ERROR << "Could not read the PE Header." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	if (peh.Signature[0] != 'P' || peh.Signature[1] != 'E' || peh.Signature[2] != '\x00' || peh.Signature[3] != '\x00')
	{
		PRINT_ERROR << "PE Header is invalid." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	_h_pe.reset(peh);
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_coff_symbols()
{
	if (!_h_pe || _file_handle == nullptr) {
		return false;
	}

	if (_h_pe->NumberOfSymbols == 0 || _h_pe->PointerToSymbolTable == 0) {
		return true;
	}

	if (fseek(_file_handle.get(), _h_pe->PointerToSymbolTable, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach PE COFF symbols (fseek to offset " <<  _h_pe->PointerToSymbolTable << " failed)."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	for (unsigned int i = 0 ; i < _h_pe->NumberOfSymbols ; ++i)
	{
		pcoff_symbol sym = boost::make_shared<coff_symbol>();
		memset(sym.get(), 0, sizeof(coff_symbol));

		if (18 != fread(sym.get(), 1, 18, _file_handle.get())) // Each symbol has a fixed size of 18 bytes.
		{
			PRINT_ERROR << "Could not read a COFF symbol." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		if (sym->SectionNumber > _sections.size())
		{
			PRINT_WARNING << "COFF symbol's section number is bigger than the number of sections!"
						  << DEBUG_INFO_INSIDEPE << std::endl;
			continue;
		}

		_coff_symbols.push_back(sym);
	}

	// Read the COFF string table
	size_t st_size = 0;
	size_t count = 0;
	fread(&st_size, 4, 1, _file_handle.get());
	if (st_size > get_filesize() - ftell(_file_handle.get())) // Weak error check, but I couldn't find a better one in the PE spec.
	{
		PRINT_WARNING << "COFF String Table's reported size is bigger than the remaining bytes!"
					  << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	while (count < st_size)
	{
		pString s = boost::make_shared<std::string>(utils::read_ascii_string(_file_handle.get()));
		_coff_string_table.push_back(s);
		count += s->size() + 1; // Count the null terminator as well.
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_image_optional_header()
{
	if (!_h_pe || _file_handle == nullptr) {
		return false;
	}

	image_optional_header ioh;
	memset(&ioh, 0, sizeof(ioh));

	if (_h_pe->SizeOfOptionalHeader == 0)
	{
		PRINT_WARNING << "This PE has no Image Optional Header!." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	if (fseek(_file_handle.get(), _h_dos->e_lfanew + sizeof(pe_header), SEEK_SET))
	{
		PRINT_ERROR << "Could not reach the Image Optional Header (fseek to offset "
			<<  _h_dos->e_lfanew + sizeof(pe_header) << " failed)." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	// Only read the first 0x18 bytes: after that, we have to fill the fields manually.
	if (0x18 != fread(&ioh, 1, 0x18, _file_handle.get()))
	{
		PRINT_ERROR << "Could not read the Image Optional Header." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (ioh.Magic != nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32") && ioh.Magic != nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+"))
	{
		PRINT_ERROR << "Invalid Image Optional Header magic." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	else if (ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32"))
	{
		if (4 != fread(&ioh.BaseOfData, 1, 4, _file_handle.get()) || 4 != fread(&ioh.ImageBase, 1, 4, _file_handle.get()))
		{
			PRINT_ERROR << "Error reading the PE32 specific part of ImageOptionalHeader."
						<< DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
	}
	else
	{
		// PE32+: BaseOfData doesn't exist, and ImageBase is a uint64.
		if (8 != fread(&ioh.ImageBase, 1, 8, _file_handle.get()))
		{
			PRINT_ERROR << "Error reading the PE32+ specific part of ImageOptionalHeader."
						<< DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
	}

	// After this, PE32 and PE32+ structures are in sync for a while.
	if (0x28 != fread(&ioh.SectionAlignment, 1, 0x28, _file_handle.get()))
	{
		PRINT_ERROR << "Error reading the common part of ImageOptionalHeader."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	// Reject malformed executables
	if (ioh.FileAlignment == 0 || ioh.SectionAlignment == 0)
	{
		PRINT_ERROR << "FileAlignment or SectionAlignment is null: the PE is invalid."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	// The next 4 values may be uint32s or uint64s depending on whether this is a PE32+ header.
	// We store them in uint64s in any case.
	if (ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+"))
	{
		if (40 != fread(&ioh.SizeofStackReserve, 1, 40, _file_handle.get()))
		{
			PRINT_ERROR << "Error reading SizeOfStackReserve for a PE32+ IMAGE OPTIONAL HEADER."
						<< DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
	}
	else
	{
		fread(&ioh.SizeofStackReserve, 1, 4, _file_handle.get());
		fread(&ioh.SizeofStackCommit, 1, 4, _file_handle.get());
		fread(&ioh.SizeofHeapReserve, 1, 4, _file_handle.get());
		fread(&ioh.SizeofHeapCommit, 1, 4, _file_handle.get());
		fread(&ioh.LoaderFlags, 1, 4, _file_handle.get());
		fread(&ioh.NumberOfRvaAndSizes, 1, 4, _file_handle.get());
		if (feof(_file_handle.get()) || ferror(_file_handle.get()))
		{
			PRINT_ERROR << "Error reading SizeOfStackReserve for a PE32 IMAGE OPTIONAL HEADER." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
	}

	// The Windows Loader disregards the value if it is greater than 0x10. This trick is supposedly used to crash parsers.
	// Source: http://opcode0x90.wordpress.com/2007/04/22/windows-loader-does-it-differently/
	// TODO: Move to an analysis module, since this denotes a suspicious intent.
	if (ioh.NumberOfRvaAndSizes > 0x10) {
		PRINT_WARNING << "NumberOfRvaAndSizes > 0x10. This PE may have manually been crafted." << DEBUG_INFO_INSIDEPE << std::endl;
	}

	for (unsigned int i = 0 ; i < std::min(ioh.NumberOfRvaAndSizes, static_cast<boost::uint32_t>(0x10)) ; ++i)
	{
		if (8 != fread(&ioh.directories[i], 1, 8, _file_handle.get()))
		{
			PRINT_ERROR << "Could not read directory entry " << i << "." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
	}

	_ioh.reset(ioh);
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_section_table()
{
	if (!_h_pe || !_h_dos || _file_handle == nullptr) {
		return false;
	}

	if (fseek(_file_handle.get(), _h_dos->e_lfanew + sizeof(pe_header) + _h_pe->SizeOfOptionalHeader, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach the Section Table (fseek to offset "
					<<  _h_dos->e_lfanew + sizeof(pe_header) + _h_pe->SizeOfOptionalHeader << " failed)."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	for (int i = 0 ; i < _h_pe->NumberofSections ; ++i)
	{
		image_section_header sec;
		memset(&sec, 0, sizeof(image_section_header));
		if (sizeof(image_section_header) != fread(&sec, 1, sizeof(image_section_header), _file_handle.get()))
		{
			PRINT_ERROR << "Could not read section " << i << "." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
		_sections.push_back(boost::make_shared<Section>(sec, _file_handle, _file_size, _coff_string_table));
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_debug()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}
	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_DEBUG)) { // No debug information.
		return true;
	}

	unsigned int size = 6 * sizeof(boost::uint32_t) + 2 * sizeof(boost::uint16_t);
	unsigned int number_of_entries = _ioh->directories[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / size;

	for (unsigned int i = 0 ; i < number_of_entries ; ++i)
	{
		auto debug = boost::make_shared<debug_directory_entry>();
		memset(debug.get(), 0, size);
		if (size != fread(debug.get(), 1, size, _file_handle.get()))
		{
			PRINT_ERROR << "Could not read the DEBUG_DIRECTORY_ENTRY" << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		// VC++ Debug information
		if (debug->Type == nt::DEBUG_TYPES.at("IMAGE_DEBUG_TYPE_CODEVIEW"))
		{
			pdb_info pdb;
			unsigned int pdb_size = 2 * sizeof(boost::uint32_t) + 16 * sizeof(boost::uint8_t);
			memset(&pdb, 0, pdb_size);

			unsigned int saved_offset = ftell(_file_handle.get());
			fseek(_file_handle.get(), debug->PointerToRawData, SEEK_SET);
			if (pdb_size != fread(&pdb, 1, pdb_size, _file_handle.get()) ||
				(pdb.Signature != 0x53445352 && pdb.Signature != 0x3031424E)) // Signature: "RSDS" or "NB10"
			{
				PRINT_ERROR << "Could not read PDB file information of invalid magic number."
							<< DEBUG_INFO_INSIDEPE << std::endl;
				return false;
			}
			pdb.PdbFileName = utils::read_ascii_string(_file_handle.get());	// Not optimal, but it'll help if I decide to
																			// further parse these debug sub-structures.
			debug->Filename = pdb.PdbFileName;
			fseek(_file_handle.get(), saved_offset, SEEK_SET);
		}
		else if (debug->Type == nt::DEBUG_TYPES.at("IMAGE_DEBUG_TYPE_MISC"))
		{
			image_debug_misc misc;
			unsigned int misc_size = 2 * sizeof(boost::uint32_t) + 4 * sizeof(boost::uint8_t);
			memset(&misc, 1, misc_size);
			unsigned int saved_offset = ftell(_file_handle.get());
			fseek(_file_handle.get(), debug->PointerToRawData, SEEK_SET);
			if (misc_size != fread(&misc, 1, misc_size, _file_handle.get()))
			{
				PRINT_ERROR << "Could not read DBG file information" << DEBUG_INFO_INSIDEPE << std::endl;
				return false;
			}
			switch (misc.Unicode)
			{
			case 1:
				misc.DbgFile = utils::read_unicode_string(_file_handle.get(), misc.Length - misc_size);
				break;
			case 0:
				misc.DbgFile = utils::read_ascii_string(_file_handle.get(), misc.Length - misc_size);
				break;
			}
			debug->Filename = misc.DbgFile;
			fseek(_file_handle.get(), saved_offset, SEEK_SET);
		}
		_debug_entries.push_back(debug);
	}

	return true;
}

// ----------------------------------------------------------------------------

unsigned int PE::rva_to_offset(boost::uint64_t rva) const
{
	if (!_ioh) // Image Optional Header was not parsed.
	{
		PRINT_ERROR << "Tried to convert a RVA into an offset, but ImageOptionalHeader was not parsed!"
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return 0;
	}

	// Special case: PE with no sections
	if (_sections.empty()) {
		return rva & 0xFFFFFFFF; // If the file is bigger than 4GB, this assumption may not be true.
	}

	// Find the corresponding section.
	pSection section = pSection();
	for (const auto& it : _sections)
	{
		if (is_address_in_section(rva, it))
		{
			section = it;
			break;
		}
	}

	if (section == nullptr)
	{
		// No section found. Maybe the VirsualSize is erroneous? Try with the RawSizeOfData.
		for (const auto& it : _sections)
		{
			if (is_address_in_section(rva, it, true))
			{
				section = it;
				break;
			}
		}

		if (section == nullptr) {  // No section matches the RVA.
			return 0;
		}
	}

	// The sections have to be aligned on FileAlignment bytes.
	// TODO: Move warning to a plugin?
	if (section->get_pointer_to_raw_data() % _ioh->FileAlignment != 0)
	{
		PRINT_WARNING << "The PE's sections are not aligned to its reported FileAlignment. "
					  << "It was almost certainly crafted manually."
					  << DEBUG_INFO_INSIDEPE << std::endl;
		int new_raw_pointer = (section->get_pointer_to_raw_data() / _ioh->FileAlignment) * _ioh->FileAlignment;
		return (rva - section->get_virtual_address() + new_raw_pointer) & 0xFFFFFFFF;
	}

	// Assume that the offset in the file can be stored inside an unsigned integer.
	// PEs whose size is bigger than 4 Go may not be parsed properly.
	return (rva - section->get_virtual_address() + section->get_pointer_to_raw_data()) & 0xFFFFFFFF;
}

// ----------------------------------------------------------------------------

unsigned int PE::_va_to_offset(boost::uint64_t va) const
{
	if (!_ioh) // Image Optional Header was not parsed.
	{
		PRINT_ERROR << "Tried to convert a VA into an offset, but ImageOptionalHeader was not parsed!"
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return 0;
	}
	return va > _ioh->ImageBase ? rva_to_offset(va - _ioh->ImageBase) : 0;
}

// ----------------------------------------------------------------------------

bool PE::_reach_directory(int directory) const
{
	if (_file_handle == nullptr) {
		return false;
	}

	if (directory > 0x10) // There can be no more than 16 directories.
	{
		PRINT_WARNING << "Tried to reach directory " << directory << ", maximum is 16."
					  << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (!_ioh) // Image Optional Header was not parsed.
	{
		PRINT_ERROR << "Tried to reach a directory, but ImageOptionalHeader was not parsed!"
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (_ioh->directories[directory].VirtualAddress == 0 && _ioh->directories[directory].Size == 0) {
		return false; // Requested directory is empty.
	}
	else if (_ioh->directories[directory].Size == 0) // Weird, but continue anyway.
	{
		PRINT_WARNING << "directory " << directory << " has a size of 0! This PE may have been manually crafted!"
					  << DEBUG_INFO_INSIDEPE << std::endl;
	}
	else if (_ioh->directories[directory].VirtualAddress == 0)
	{
		PRINT_ERROR << "directory " << directory << " has a RVA of 0 but a non-null size."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	unsigned int offset = rva_to_offset(_ioh->directories[directory].VirtualAddress);

	if (!offset || fseek(_file_handle.get(), offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach the requested directory (offset=0x" << std::hex << offset << ")."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_directories()
{
	if (_file_handle == nullptr) {
		return false;
	}

	return _parse_imports() &&
		   _parse_delayed_imports() &&
		   _parse_exports() &&
		   _parse_resources() &&
		   _parse_debug() &&
		   _parse_relocations() &&
		   _parse_tls() &&
		   _parse_config() &&
		   _parse_certificates() &&
		   _parse_rich_header();
}

// ----------------------------------------------------------------------------

bool PE::_parse_exports()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}
	image_export_directory ied;

	// Don't overwrite the std::string at the end of the structure.
	unsigned int ied_size = 9*sizeof(boost::uint32_t) + 2*sizeof(boost::uint16_t);
	memset(&ied, 0, ied_size);

	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_EXPORT))	{
		return true; // No exports
	}

	if (ied_size != fread(&ied, 1, ied_size, _file_handle.get()))
	{
		PRINT_ERROR << "Could not read the IMAGE_EXPORT_DIRECTORY." << std::endl;
		return false;
	}

    _ied.reset(ied);

	if (_ied->Characteristics != 0) {
		PRINT_WARNING << "IMAGE_EXPORT_DIRECTORY field Characteristics is reserved and should be 0!"
					  << DEBUG_INFO_INSIDEPE << std::endl; // TODO: Move to structural plugin?
	}
	if (_ied->NumberOfFunctions == 0) {
		return true; // No exports
	}

	// Read the export name
	unsigned int offset = rva_to_offset(_ied->Name);
	if (!offset || !utils::read_string_at_offset(_file_handle.get(), offset, _ied->NameStr))
	{
		PRINT_ERROR << "Could not read the exported DLL name." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	// Get the address and ordinal of each exported function
	offset = rva_to_offset(_ied->AddressOfFunctions);
	if (!offset || fseek(_file_handle.get(), offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach exported functions address table."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	for (unsigned int i = 0 ; i < _ied->NumberOfFunctions ; ++i)
	{
		pexported_function ex = boost::make_shared<exported_function>();
		if (4 != fread(&(ex->Address), 1, 4, _file_handle.get()))
		{
			PRINT_ERROR << "Could not read an exported function's address."
						<< DEBUG_INFO_INSIDEPE << std::endl;
			return true;
		}
		ex->Ordinal = _ied->Base + i;

		// If the address is located in the export directory, then it is a forwarded export.
		image_data_directory export_dir = _ioh->directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (ex->Address > export_dir.VirtualAddress && ex->Address < export_dir.VirtualAddress + export_dir.Size)
		{
			offset = rva_to_offset(ex->Address);
			if (!offset || !utils::read_string_at_offset(_file_handle.get(), offset, ex->ForwardName))
			{
				PRINT_ERROR << "Could not read a forwarded export name." << DEBUG_INFO_INSIDEPE << std::endl;
				return true;
			}
		}

		_exports.push_back(ex);
	}

    if (_ied->NumberOfNames == 0) {
        return true;
    }

	// Associate possible exported names with the RVAs we just obtained. First, read the name and ordinal table.
	boost::scoped_array<boost::uint32_t> names;
	boost::scoped_array<boost::uint16_t> ords;
	try
	{
		// ied.NumberOfNames is an untrusted value. Allocate in a try-catch block to prevent crashes. See issue #1.
		names.reset(new boost::uint32_t[_ied->NumberOfNames]);
		ords.reset(new boost::uint16_t[_ied->NumberOfNames]);
	}
	catch (const std::bad_alloc&)
	{
		PRINT_ERROR << "Could not allocate an array big enough to hold exported name RVAs. This PE may have been manually crafted."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}
	offset = rva_to_offset(_ied->AddressOfNames);
	if (!offset || fseek(_file_handle.get(), offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach exported function's name table." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	if (_ied->NumberOfNames * sizeof(boost::uint32_t) != fread(names.get(), 1, _ied->NumberOfNames * sizeof(boost::uint32_t), _file_handle.get()))
	{
		PRINT_ERROR << "Could not read an exported function's name address." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	offset = rva_to_offset(_ied->AddressOfNameOrdinals);
	if (!offset || fseek(_file_handle.get(), offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach exported functions NameOrdinals table." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}
	if (_ied->NumberOfNames * sizeof(boost::uint16_t) != fread(ords.get(), 1, _ied->NumberOfNames * sizeof(boost::uint16_t), _file_handle.get()))
	{
		PRINT_ERROR << "Could not read an exported function's name ordinal." << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	// Now match the names with with the exported addresses.
	for (unsigned int i = 0 ; i < _ied->NumberOfNames ; ++i)
	{
		offset = rva_to_offset(names[i]);
		if (!offset || ords[i] >= _exports.size() || !utils::read_string_at_offset(_file_handle.get(), offset, _exports.at(ords[i])->Name))
		{
			PRINT_ERROR << "Could not match an export name with its address!" << DEBUG_INFO_INSIDEPE << std::endl;
			return true;
		}
	}
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_relocations()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}

	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC))	{ // No relocation table
		return true;
	}

	unsigned int remaining_size = _ioh->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	unsigned int header_size =  2*sizeof(boost::uint32_t);
	while (remaining_size > 0)
	{
		pimage_base_relocation reloc = boost::make_shared<image_base_relocation>();
		memset(reloc.get(), 0, header_size);
		if (header_size != fread(reloc.get(), 1, header_size, _file_handle.get()) || reloc->BlockSize > remaining_size)
		{
			PRINT_ERROR << "Could not read an IMAGE_BASE_RELOCATION!" << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		// It seems that sometimes, the end of the section is padded with zeroes. Break here
		// instead of reaching EOF. I have encountered this oddity in 4d7ca8d467770f657305c16474b845fe.
		if (reloc->BlockSize == 0) {
			return true;
		}

		// The remaining fields are an array of shorts. The number is deduced from the block size.
		for (unsigned int i = 0 ; i < (reloc->BlockSize - header_size) / sizeof(boost::uint16_t) ; ++i)
		{
			boost::uint16_t type_or_offset = 0;
			if (sizeof(boost::uint16_t) != fread(&type_or_offset, 1, sizeof(boost::uint16_t), _file_handle.get()))
			{
				PRINT_ERROR << "Could not read an IMAGE_BASE_RELOCATION's TypeOrOffset!"
							<< DEBUG_INFO_INSIDEPE << std::endl;
				return false;
			}
			reloc->TypesOffsets.push_back(type_or_offset);
		}

		_relocations.push_back(reloc);
		remaining_size -= reloc->BlockSize;
	}
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_tls()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}

	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_TLS))	{ // No TLS callbacks
		return true;
	}

	image_tls_directory tls;
	unsigned int size = 4*sizeof(boost::uint64_t) + 2*sizeof(boost::uint32_t);
	memset(&tls, 0, size);

	if (get_architecture() == x64) {
		fread(&tls, 1, size, _file_handle.get());
	}
	else
	{
		fread(&tls.StartAddressOfRawData, 1, sizeof(boost::uint32_t), _file_handle.get());
		fread(&tls.EndAddressOfRawData, 1, sizeof(boost::uint32_t), _file_handle.get());
		fread(&tls.AddressOfIndex, 1, sizeof(boost::uint32_t), _file_handle.get());
		fread(&tls.AddressOfCallbacks, 1, sizeof(boost::uint32_t), _file_handle.get());
		fread(&tls.SizeOfZeroFill, 1, 2 * sizeof(boost::uint32_t), _file_handle.get());
	}

	if (feof(_file_handle.get()) || ferror(_file_handle.get()))
	{
		PRINT_ERROR << "Could not read the IMAGE_TLS_DIRECTORY." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	// Go to the offset table
	unsigned int offset = _va_to_offset(tls.AddressOfCallbacks);
	if (!offset || fseek(_file_handle.get(), offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach the TLS callback table." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	boost::uint64_t callback_address = 0;
	unsigned int callback_size = _ioh->Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+") ? sizeof(boost::uint64_t) : sizeof(boost::uint32_t);
	while (true) // break on null callback
	{
		if (callback_size != fread(&callback_address, 1, callback_size, _file_handle.get()) || !callback_address) { // Exit condition.
			break;
		}
		tls.Callbacks.push_back(callback_address);
	}

	_tls.reset(tls);
	return true;
}

// ----------------------------------------------------------------------------

/**
 *	@brief	Helper function which simplifies the process of reading a field from
 *			the file's load configuration while checking if there are enough
 *			bytes available.
 *			
 *	@param	config		The structure that was read so far.
 *	@param	source		A pointer to the file to read from.
 *	@param	destination	Where the read value is to be put.
 *	@param	field_size	The size of the value to read.
 *	@param	read_bytes	The number of bytes read so far, will be incremented.
 *	
 *	@return	Whether the value should be read. If false, EOF has been reached or
 *			the structure has no more fields to read.
 */
bool read_config_field(const			image_load_config_directory& config,
					   FILE*			source,
					   void*			destination,
					   unsigned int		field_size,
					   unsigned int&	read_bytes)
{
	if (read_bytes + field_size > config.Size) {
		return false;
	}
	if (1 != fread(destination, field_size, 1, source))	{
		return false;
	}
	read_bytes += field_size;
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_config()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}

	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)) { // No TLS callbacks
		return true;
	}

	image_load_config_directory config;
	memset(&config, 0, sizeof(config));
	if (24 != fread(&config, 1, 24, _file_handle.get()))
	{
		PRINT_WARNING << "Error while reading the IMAGE_LOAD_CONFIG_DIRECTORY!"
					  << DEBUG_INFO_INSIDEPE << std::endl;
		return true; // Non fatal
	}

	// The next few fields are uint32s or uint64s depending on the architecture.
	unsigned int field_size = (_ioh->Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32")) ? 4 : 8;
	if (1 != fread(&config.DeCommitFreeBlockThreshold, field_size, 1, _file_handle.get()) ||
		1 != fread(&config.DeCommitTotalFreeThreshold, field_size, 1, _file_handle.get()) ||
		1 != fread(&config.LockPrefixTable, field_size, 1, _file_handle.get()) ||
		1 != fread(&config.MaximumAllocationSize, field_size, 1, _file_handle.get()) ||
		1 != fread(&config.VirtualMemoryThreshold, field_size, 1, _file_handle.get()) ||
		1 != fread(&config.ProcessAffinityMask, field_size, 1, _file_handle.get()))
	{
		PRINT_WARNING << "Error while reading the IMAGE_LOAD_CONFIG_DIRECTORY!"
			<< DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	// Then a few fields have the same size on x86 and x64.
	if (8 != fread(&config.ProcessHeapFlags, 1, 8, _file_handle.get()))
	{
		PRINT_WARNING << "Error while reading the IMAGE_LOAD_CONFIG_DIRECTORY!"
			<< DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	// The last fields have a variable size depending on the architecture again.
	if (1 != fread(&config.EditList, field_size, 1, _file_handle.get()) ||
		1 != fread(&config.SecurityCookie, field_size, 1, _file_handle.get()))
	{
		PRINT_WARNING << "Error while reading the IMAGE_LOAD_CONFIG_DIRECTORY!"
			<< DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}
	unsigned int read_bytes = 32 + 8 * field_size; // The number of bytes read so far

	// SafeSEH information may not be present in some XP-era binaries.
	// The MSDN page for IMAGE_LOAD_CONFIG_DIRECTORY specifies that their size must be 64
	// (https://msdn.microsoft.com/en-us/library/windows/desktop/ms680328(v=vs.85).aspx).
	// Those fields should be 0 in 64 bit binaries.
	if (config.Size > read_bytes)
	{
		if (1 != fread(&config.SEHandlerTable, field_size, 1, _file_handle.get()) ||
			1 != fread(&config.SEHandlerCount, field_size, 1, _file_handle.get()))
		{
			PRINT_WARNING << "Error while reading the IMAGE_LOAD_CONFIG_DIRECTORY!"
				<< DEBUG_INFO_INSIDEPE << std::endl;
			return true;
		}
	}
	read_bytes += 2 * field_size;

	// Read the remaining fields. The OR operator allows this code to stop whenever a read returns false, 
	// i.e. when trying to read more bytes than are available in the structure. This construction is necessary
	// because fields are added to the structure as Windows evolves.
	read_config_field(config, _file_handle.get(), &config.GuardCFCheckFunctionPointer, field_size, read_bytes) ||
	read_config_field(config, _file_handle.get(), &config.GuardCFDispatchFunctionPointer, field_size, read_bytes) ||
	read_config_field(config, _file_handle.get(), &config.GuardCFFunctionTable, field_size, read_bytes) ||
	read_config_field(config, _file_handle.get(), &config.GuardCFFunctionCount, field_size, read_bytes) ||
	read_config_field(config, _file_handle.get(), &config.GuardFlags, 4, read_bytes) ||
	read_config_field(config, _file_handle.get(), &config.CodeIntegrity, 12, read_bytes) ||
	read_config_field(config, _file_handle.get(), &config.GuardAddressTakenIatEntryTable, field_size, read_bytes) ||
	read_config_field(config, _file_handle.get(), &config.GuardAddressTakenIatEntryCount, field_size, read_bytes) ||
	read_config_field(config, _file_handle.get(), &config.GuardLongJumpTargetTable, field_size, read_bytes) ||
	read_config_field(config, _file_handle.get(), &config.GuardLongJumpTargetCount, field_size, read_bytes);

	_config.reset(config);
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_certificates()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}

	if (!_ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress ||		// In this case, "VirtualAddress" is actually a file offset.
		fseek(_file_handle.get(), _ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress, SEEK_SET))
	{
		return true;	// Unsigned binary
	}

	unsigned int remaining_bytes = _ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
	unsigned int header_size = sizeof(boost::uint32_t) + 2*sizeof(boost::uint16_t);
	while (remaining_bytes > header_size)
	{
		pwin_certificate cert = boost::make_shared<win_certificate>();
		memset(cert.get(), 0, header_size);
		if (header_size != fread(cert.get(), 1, header_size, _file_handle.get()))
		{
			PRINT_WARNING << "Could not read a WIN_CERTIFICATE's header." << std::endl;
			return true; // Recoverable error.
		}

		// The certificate may point to garbage. Although other values than the ones defined in nt_values.h
		// are allowed by the PE specification (but which ones?), this is a good heuristic to determine
		// whether we have landed in random bytes.
		if (*nt::translate_to_flag(cert->CertificateType, nt::WIN_CERTIFICATE_TYPES) == "UNKNOWN" &&
			*nt::translate_to_flag(cert->Revision, nt::WIN_CERTIFICATE_REVISIONS) == "UNKNOWN")
		{
			PRINT_WARNING << "The WIN_CERTIFICATE appears to be invalid." << DEBUG_INFO_INSIDEPE << std::endl;
			return true; // Recoverable error.
		}
		else if (cert->CertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA)
		{
			PRINT_WARNING << "Encountered a certificate of type " 
						  << *nt::translate_to_flag(cert->CertificateType, nt::WIN_CERTIFICATE_TYPES)
						  << ", but only WIN_CERT_TYPE_PKCS_SIGNED_DATA is supported by Windows!"
						  << DEBUG_INFO_INSIDEPE << std::endl;
			// Get the certificate data anyway.
		}

		try {
			cert->Certificate.resize(cert->Length);
		}
		catch (const std::exception& e)
		{
			PRINT_ERROR << "Failed to allocate enough space for a certificate! (" << e.what() << ")"
						<< DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		if (cert->Length < remaining_bytes ||
			cert->Length - header_size != fread(&(cert->Certificate[0]), 1, cert->Length - header_size, _file_handle.get()))
		{
			PRINT_ERROR << "Could not read a WIN_CERTIFICATE's data."
						<< DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
		remaining_bytes -= cert->Length;
		_certificates.push_back(cert);

		// The certificates start on 8-byte aligned addresses
		unsigned int padding = cert->Length % 8;
		if (padding && remaining_bytes)
		{
			fseek(_file_handle.get(), padding, SEEK_CUR);
			remaining_bytes -= padding;
		}
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_rich_header()
{
	if (!_h_dos || _file_handle == nullptr) {
		return false;
	}

	// Start searching for the RICH header at offset 0, but before the PE header.
	if (fseek(_file_handle.get(), 0, SEEK_SET))	{
		return true;
	}

	unsigned int read;
	int bytes_left = _h_dos->e_lfanew;

	do
	{
		if (1 != fread(&read, 4, 1, _file_handle.get())) {
			break;
		}
		bytes_left -= 4;  // Stay between offset 0x80 and the PE header.
	} while (read != 0x68636952 && bytes_left > 0);

	if (read != 0x68636952)	{
		return true;  // The RICH magic was not found.
	}
	rich_header h;
	if (1 != fread(&h.xor_key, 4, 1, _file_handle.get())) 
	{
		PRINT_WARNING << "XOR key absent after the RICH header!" << DEBUG_INFO_INSIDEPE << std::endl;
		return true;
	}

	// Start parsing the values backwards.
	while (true)
	{
		if (fseek(_file_handle.get(), -16, SEEK_CUR)) 
		{
			PRINT_WARNING << "Error while reading the RICH header!" << DEBUG_INFO_INSIDEPE << std::endl;
			return true;
		}
		boost::uint64_t data;
		if (1 != fread(&data, 8, 1, _file_handle.get())) 
		{
			PRINT_WARNING << "Error while reading the RICH header!" << DEBUG_INFO_INSIDEPE << std::endl;
			return true;
		}
		boost::uint32_t count = (data >> 32) ^ h.xor_key;
		boost::uint32_t id_value = (data & 0xFFFFFFFF) ^ h.xor_key;

		// Stop if we reach the start marker, "DanS".
		if (id_value == 0x536E6144) {
			break;
		}
		auto t = std::make_tuple(static_cast<boost::uint16_t>((id_value >> 16) & 0xFFFF), static_cast<boost::uint16_t>(id_value & 0xFFFF), count);
		h.values.insert(h.values.begin(), t);
	};

	// Keep a trace of where this header starts, as it is not easy to locate and is useful to calculate the checksum.
	h.file_offset = ftell(_file_handle.get()) - 8;
	_rich_header.reset(h);
	return true;
}

} // !namespace mana
