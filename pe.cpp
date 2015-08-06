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

#include "pe.h"

// TODO: Remove when Yara doesn't mask min & max anymore
#undef min
#undef max

namespace sg {

PE::PE(const std::string& path)
	: _path(path), _initialized(false)
{
	FILE* f = fopen(_path.c_str(), "rb");
	if (f == NULL)
	{
		PRINT_ERROR << "Could not open " << _path << "." << std::endl;
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

	// Failure is acceptable from here on.
	_initialized = true;
	_parse_coff_symbols(f);
	_parse_directories(f);

	END:
	if (f != NULL) {
		fclose(f);
	}
}

// ----------------------------------------------------------------------------

boost::shared_ptr<PE> PE::create(const std::string& path) {
	return boost::shared_ptr<PE>(new PE(path));
}

// ----------------------------------------------------------------------------

void* PE::operator new(size_t size)
{
	void* p = malloc(size);
	if (p == NULL)
		throw std::bad_alloc();
	return p;
}

// ----------------------------------------------------------------------------

void PE::operator delete(void* p) {
	free(p);
}


// ----------------------------------------------------------------------------

size_t PE::get_filesize() const
{
	FILE* f = fopen(_path.c_str(), "rb");
	size_t res = 0;
	if (f == NULL) {
		return res;
	}
	fseek(f, 0, SEEK_END);
	res = ftell(f);
	fclose(f);
	return res;
}

// ----------------------------------------------------------------------------

bool PE::_parse_dos_header(FILE* f)
{
	dos_header dos;
	memset(&dos, 0, sizeof(dos));
	if (sizeof(dos) > get_filesize())
	{
		PRINT_ERROR << "Input file is too small to be a valid PE." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (sizeof(dos) != fread(&dos, 1, sizeof(dos), f))
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

bool PE::_parse_pe_header(FILE* f)
{
	if (!_h_dos) {
		return false;
	}

	pe_header peh;
	memset(&peh, 0, sizeof(peh));

	if (fseek(f, _h_dos->e_lfanew, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach PE header (fseek to offset " <<  _h_dos->e_lfanew << " failed)." << std::endl;
		return false;
	}
	if (sizeof(peh) != fread(&peh, 1, sizeof(peh), f))
	{
		PRINT_ERROR << "Could not read the PE Header." << std::endl;
		return false;
	}
	if (peh.Signature[0] != 'P' || peh.Signature[1] != 'E' || peh.Signature[2] != '\x00' || peh.Signature[3] != '\x00')
	{
		PRINT_ERROR << "PE Header is invalid." << std::endl;
		return false;
	}
	_h_pe.reset(peh);
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_coff_symbols(FILE* f)
{
	if (!_h_pe) {
		return false;
	}

	if (_h_pe->NumberOfSymbols == 0 || _h_pe->PointerToSymbolTable == 0) {
		return true;
	}

	if (fseek(f, _h_pe->PointerToSymbolTable, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach PE COFF symbols (fseek to offset " <<  _h_pe->PointerToSymbolTable << " failed)." << std::endl;
		return false;
	}

	for (unsigned int i = 0 ; i < _h_pe->NumberOfSymbols ; ++i)
	{
		pcoff_symbol sym = pcoff_symbol(new coff_symbol);
		memset(sym.get(), 0, sizeof(coff_symbol));

		if (18 != fread(sym.get(), 1, 18, f)) // Each symbol has a fixed size of 18 bytes.
		{
			PRINT_ERROR << "Could not read a COFF symbol." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		if (sym->SectionNumber > _sections.size())
		{
			PRINT_WARNING << "COFF symbol's section number is bigger than the number of sections!" << DEBUG_INFO_INSIDEPE << std::endl;
			continue;
		}

		_coff_symbols.push_back(sym);
	}

	// Read the COFF string table
	boost::uint32_t st_size = 0;
	boost::uint32_t count = 0;
	fread(&st_size, 4, 1, f);
	if (st_size > get_filesize() - ftell(f)) // Weak error check, but I couldn't find a better one in the PE spec.
	{
		PRINT_WARNING << "COFF String Table's reported size is bigger than the remaining bytes!" << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	while (count < st_size)
	{
		pString s = pString(new std::string(utils::read_ascii_string(f)));
		_coff_string_table.push_back(s);
		count += s->size() + 1; // Count the null terminator as well.
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_image_optional_header(FILE* f)
{
	if (!_h_pe) {
		return false;
	}

	image_optional_header ioh;
	memset(&ioh, 0, sizeof(ioh));

	if (_h_pe->SizeOfOptionalHeader == 0)
	{
		PRINT_WARNING << "This PE has no Image Optional Header!." << std::endl;
		return true;
	}

	if (fseek(f, _h_dos->e_lfanew + sizeof(pe_header), SEEK_SET))
	{
		PRINT_ERROR << "Could not reach the Image Optional Header (fseek to offset "
			<<  _h_dos->e_lfanew + sizeof(pe_header) << " failed)." << std::endl;
		return false;
	}

	// Only read the first 0x18 bytes: after that, we have to fill the fields manually.
	if (0x18 != fread(&ioh, 1, 0x18, f))
	{
		PRINT_ERROR << "Could not read the Image Optional Header." << std::endl;
		return false;
	}

	if (ioh.Magic != nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32") && ioh.Magic != nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+"))
	{
		PRINT_ERROR << "Invalid Image Optional Header magic." << std::endl;
		return false;
	}
	else if (ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32"))
	{
		if (4 != fread(&ioh.BaseOfData, 1, 4, f) || 4 != fread(&ioh.ImageBase, 1, 4, f))
		{
			PRINT_ERROR << "Error reading the PE32 specific part of ImageOptionalHeader." << std::endl;
			return false;
		}
	}
	else
	{
		// PE32+: BaseOfData doesn't exist, and ImageBase is a uint64.
		if (8 != fread(&ioh.ImageBase, 1, 8, f))
		{
			PRINT_ERROR << "Error reading the PE32+ specific part of ImageOptionalHeader." << std::endl;
			return false;
		}
	}

	// After this, PE32 and PE32+ structures are in sync for a while.
	if (0x28 != fread(&ioh.SectionAlignment, 1, 0x28, f))
	{
		PRINT_ERROR << "Error reading the common part of ImageOptionalHeader." << std::endl;
		return false;
	}

	// Reject malformed executables
	if (ioh.FileAlignment == 0 || ioh.SectionAlignment == 0)
	{
		PRINT_ERROR << "FileAlignment or SectionAlignment is null: the PE is invalid." << std::endl;
		return false;
	}

	// The next 4 values may be uint32s or uint64s depending on whether this is a PE32+ header.
	// We store them in uint64s in any case.
	if (ioh.Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+"))
	{
		if (40 != fread(&ioh.SizeofStackReserve, 1, 40, f))
		{
			PRINT_ERROR << "Error reading SizeOfStackReserve for a PE32+ IMAGE OPTIONAL HEADER." << std::endl;
			return false;
		}
	}
	else
	{
		fread(&ioh.SizeofStackReserve, 1, 4, f);
		fread(&ioh.SizeofStackCommit, 1, 4, f);
		fread(&ioh.SizeofHeapReserve, 1, 4, f);
		fread(&ioh.SizeofHeapCommit, 1, 4, f);
		fread(&ioh.LoaderFlags, 1, 4, f);
		fread(&ioh.NumberOfRvaAndSizes, 1, 4, f);
		if (feof(f) || ferror(f))
		{
			PRINT_ERROR << "Error reading SizeOfStackReserve for a PE32 IMAGE OPTIONAL HEADER." << std::endl;
			return false;
		}
	}

	// The Windows Loader disregards the value if it is greater than 0x10. This trick is supposedly used to crash parsers.
	// Source: http://opcode0x90.wordpress.com/2007/04/22/windows-loader-does-it-differently/
	// TODO: Move to an analysis module, since this denotes a suspicious intent.
	if (ioh.NumberOfRvaAndSizes > 0x10) {
		PRINT_WARNING << "NumberOfRvaAndSizes > 0x10. This PE may have manually been crafted." << std::endl;
	}

	for (unsigned int i = 0 ; i < std::min(ioh.NumberOfRvaAndSizes, (boost::uint32_t) 0x10) ; ++i)
	{
		if (8 != fread(&ioh.directories[i], 1, 8, f))
		{
			PRINT_ERROR << "Could not read directory entry " << i << "." << std::endl;
			return false;
		}
	}

	_ioh.reset(ioh);
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_section_table(FILE* f)
{
	if (!_h_pe || !_h_dos) {
		return false;
	}

	if (fseek(f, _h_dos->e_lfanew + sizeof(pe_header) + _h_pe->SizeOfOptionalHeader, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach the Section Table (fseek to offset "
			<<  _h_dos->e_lfanew + sizeof(pe_header) + _h_pe->SizeOfOptionalHeader << " failed)." << std::endl;
		return false;
	}

	for (int i = 0 ; i < _h_pe->NumberofSections ; ++i)
	{
		image_section_header sec;
		memset(&sec, 0, sizeof(image_section_header));
		if (sizeof(image_section_header) != fread(&sec, 1, sizeof(image_section_header), f))
		{
			PRINT_ERROR << "Could not read section " << i << "." << std::endl;
			return false;
		}
		_sections.push_back(pSection(new Section(sec, _path, _coff_string_table)));
	}

	return true;
}

// ----------------------------------------------------------------------------

unsigned int PE::_rva_to_offset(boost::uint64_t rva) const
{
	if (!_ioh) // Image Optional Header was not parsed.
	{
		PRINT_ERROR << "Tried to convert a RVA into an offset, but ImageOptionalHeader was not parsed!"
			<< DEBUG_INFO_INSIDEPE << std::endl;
		return 0;
	}

	// Special case: PE with no sections
	if (_sections.size() == 0) {
		return rva & 0xFFFFFFFF; // If the file is bigger than 4Go, this assumption may not be true.
	}

	// Find the corresponding section.
	pSection section = pSection();
	for (std::vector<pSection>::const_iterator it = _sections.begin() ; it != _sections.end() ; ++it)
	{
		if (is_address_in_section(rva, *it))
		{
			section = *it;
			break;
		}
	}

	if (section == NULL)
	{
		// No section found. Maybe the VirsualSize is erroneous? Try with the RawSizeOfData.
		for (std::vector<pSection>::const_iterator it = _sections.begin() ; it != _sections.end() ; ++it)
		{
			if (is_address_in_section(rva, *it, true))
			{
				section = *it;
				break;
			}
		}

		if (section == NULL) {  // No section matches the RVA.
			return 0;
		}
	}

	// The sections have to be aligned on FileAlignment bytes.
	// TODO: Move warning to a plugin?
	if (section->get_pointer_to_raw_data() % _ioh->FileAlignment != 0)
	{
		PRINT_WARNING << "The PE's sections are not aligned to its reported FileAlignment. "
			<< "It was almost certainly crafted manually." << DEBUG_INFO_INSIDEPE << std::endl;
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
	return va > _ioh->ImageBase ? _rva_to_offset(va - _ioh->ImageBase) : 0;
}

// ----------------------------------------------------------------------------

bool PE::_reach_directory(FILE* f, int directory) const
{
	if (directory > 0x10) // There can be no more than 16 directories.
	{
		PRINT_WARNING << "Tried to reach directory " << directory << ", maximum is 16." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	if (!_ioh) // Image Optional Header was not parsed.
	{
		PRINT_ERROR << "Tried to reach a directory, but ImageOptionalHeader was not parsed!"
			<< DEBUG_INFO_INSIDEPE << std::endl;
		return 0;
	}

	if (_ioh->directories[directory].VirtualAddress == 0 && _ioh->directories[directory].Size == 0) {
		return false; // Requested directory is empty.
	}
	else if (_ioh->directories[directory].Size == 0) { // Weird, but continue anyway.
		PRINT_WARNING << "directory " << directory << " has a size of 0! This PE may have been manually crafted!" << std::endl;
	}
	else if (_ioh->directories[directory].VirtualAddress == 0)
	{
		PRINT_ERROR << "directory " << directory << " has a RVA of 0 but a non-null size." << std::endl;
		return false;
	}

	unsigned int offset = _rva_to_offset(_ioh->directories[directory].VirtualAddress);

	if (!offset || fseek(f, offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach the requested directory (offset=0x" << std::hex << offset << ")." << std::endl;
		return false;
	}
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_directories(FILE* f)
{
	return _parse_imports(f) &&
		   _parse_exports(f) &&
		   _parse_resources(f) &&
		   _parse_debug(f) &&
		   _parse_relocations(f) &&
		   _parse_tls(f) &&
		   _parse_certificates(f);
}

// ----------------------------------------------------------------------------

bool PE::_parse_exports(FILE* f)
{
	if (!_ioh) {
		return false;
	}
	image_export_directory ied;

	// Don't overwrite the std::string at the end of the structure.
	unsigned int ied_size = 9*sizeof(boost::uint32_t) + 2*sizeof(boost::uint16_t);
	memset(&ied, 0, ied_size);

	if (!_reach_directory(f, IMAGE_DIRECTORY_ENTRY_EXPORT))	{
		return true; // No exports
	}

	if (ied_size != fread(&ied, 1, ied_size, f))
	{
		PRINT_ERROR << "Could not read the IMAGE_EXPORT_DIRECTORY." << std::endl;
		return false;
	}

	if (ied.Characteristics != 0) {
		PRINT_WARNING << "IMAGE_EXPORT_DIRECTORY field Characteristics is reserved and should be 0!" << DEBUG_INFO_INSIDEPE << std::endl; // TODO: Move to structural plugin?
	}
	if (ied.NumberOfFunctions == 0) {
		return true; // No exports
	}

	// Read the export name
	unsigned int offset = _rva_to_offset(ied.Name);
	if (!offset || !utils::read_string_at_offset(f, offset, ied.NameStr))
	{
		PRINT_ERROR << "Could not read the exported DLL name." << std::endl;
		return false;
	}

	// Get the address and ordinal of each exported function
	offset = _rva_to_offset(ied.AddressOfFunctions);
	if (!offset || fseek(f, offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach exported functions address table." << std::endl;
		return false;
	}

	for (unsigned int i = 0 ; i < ied.NumberOfFunctions ; ++i)
	{
		pexported_function ex = pexported_function(new exported_function);
		if (4 != fread(&(ex->Address), 1, 4, f))
		{
			PRINT_ERROR << "Could not read an exported function's address." << std::endl;
			return false;
		}
		ex->Ordinal = ied.Base + i;

		// If the address is located in the export directory, then it is a forwarded export.
		image_data_directory export_dir = _ioh->directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (ex->Address > export_dir.VirtualAddress && ex->Address < export_dir.VirtualAddress + export_dir.Size)
		{
			offset = _rva_to_offset(ex->Address);
			if (!offset || !utils::read_string_at_offset(f, offset, ex->ForwardName))
			{
				PRINT_ERROR << "Could not read a forwarded export name." << std::endl;
				return false;
			}
		}

		_exports.push_back(ex);
	}

	// Associate possible exported names with the RVAs we just obtained. First, read the name and ordinal table.
	boost::scoped_array<boost::uint32_t> names(new boost::uint32_t[ied.NumberOfNames]);
	boost::scoped_array<boost::uint16_t> ords(new boost::uint16_t[ied.NumberOfNames]);
	offset = _rva_to_offset(ied.AddressOfNames);
	if (!offset || fseek(f, offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach exported function's name table." << std::endl;
		return false;
	}

	if (ied.NumberOfNames * sizeof(boost::uint32_t) != fread(names.get(), 1, ied.NumberOfNames * sizeof(boost::uint32_t), f))
	{
		PRINT_ERROR << "Could not read an exported function's name address." << std::endl;
		return false;
	}

	offset = _rva_to_offset(ied.AddressOfNameOrdinals);
	if (!offset || fseek(f, offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach exported functions NameOrdinals table." << std::endl;
		return false;
	}
	if (ied.NumberOfNames * sizeof(boost::uint16_t) != fread(ords.get(), 1, ied.NumberOfNames * sizeof(boost::uint16_t), f))
	{
		PRINT_ERROR << "Could not read an exported function's name ordinal." << std::endl;
		return false;
	}

	// Now match the names with with the exported addresses.
	for (unsigned int i = 0 ; i < ied.NumberOfNames ; ++i)
	{
		offset = _rva_to_offset(names[i]);
		if (!offset || ords[i] > _exports.size() || !utils::read_string_at_offset(f, offset, _exports.at(ords[i])->Name))
		{
			PRINT_ERROR << "Could not match an export name with its address!" << std::endl;
			return false;
		}
	}

	_ied.reset(ied);
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_relocations(FILE* f)
{
	if (!_ioh) {
		return false;
	}

	if (!_reach_directory(f, IMAGE_DIRECTORY_ENTRY_BASERELOC))	{ // No relocation table
		return true;
	}

	unsigned int remaining_size = _ioh->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	unsigned int header_size =  2*sizeof(boost::uint32_t);
	while (remaining_size > 0)
	{
		pimage_base_relocation reloc = pimage_base_relocation(new image_base_relocation);
		memset(reloc.get(), 0, header_size);
		if (header_size != fread(reloc.get(), 1, header_size, f) || reloc->BlockSize > remaining_size)
		{
			PRINT_ERROR << "Could not read an IMAGE_BASE_RELOCATION!" << std::endl;
			return false;
		}

		// The remaining fields are an array of shorts. The number is deduced from the block size.
		for (unsigned int i = 0 ; i < (reloc->BlockSize - header_size) / sizeof(boost::uint16_t) ; ++i)
		{
			boost::uint16_t type_or_offset = 0;
			if (sizeof(boost::uint16_t) != fread(&type_or_offset, 1, sizeof(boost::uint16_t), f))
			{
				PRINT_ERROR << "Could not read an IMAGE_BASE_RELOCATION's TypeOrOffset!" << std::endl;
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

bool PE::_parse_tls(FILE* f)
{
	if (!_ioh) {
		return false;
	}

	if (!_reach_directory(f, IMAGE_DIRECTORY_ENTRY_TLS))	{ // No TLS callbacks
		return true;
	}

	image_tls_directory tls;
	unsigned int size = 4*sizeof(boost::uint64_t) + 2*sizeof(boost::uint32_t);
	memset(&tls, 0, size);

	if (_ioh->Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+")) {
		fread(&tls, 1, size, f);
	}
	else
	{
		fread(&tls.StartAddressOfRawData, 1, sizeof(boost::uint32_t), f);
		fread(&tls.EndAddressOfRawData, 1, sizeof(boost::uint32_t), f);
		fread(&tls.AddressOfIndex, 1, sizeof(boost::uint32_t), f);
		fread(&tls.AddressOfCallbacks, 1, sizeof(boost::uint32_t), f);
		fread(&tls.SizeOfZeroFill, 1, 2 * sizeof(boost::uint32_t), f);
	}

	if (feof(f) || ferror(f))
	{
		PRINT_ERROR << "Could not read the IMAGE_TLS_DIRECTORY." << std::endl;
		return false;
	}

	// Go to the offset table
	unsigned int offset = _va_to_offset(tls.AddressOfCallbacks);
	if (!offset || fseek(f, offset, SEEK_SET))
	{
		PRINT_ERROR << "Could not reach the TLS callback table." << std::endl;
		return false;
	}

	boost::uint64_t callback_address = 0;
	unsigned int callback_size = _ioh->Magic == nt::IMAGE_OPTIONAL_HEADER_MAGIC.at("PE32+") ? sizeof(boost::uint64_t) : sizeof(boost::uint32_t);
	while (true) // break on null callback
	{
		if (callback_size != fread(&callback_address, 1, callback_size, f) || !callback_address) { // Exit condition.
			break;
		}
		tls.Callbacks.push_back(callback_address);
	}

	if (tls.Characteristics != 0) {
		PRINT_WARNING << "TLS Directory 'Characteristics' is reserved and should be 0." << DEBUG_INFO_INSIDEPE << std::endl;
	}

	_tls.reset(tls);
	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_certificates(FILE* f)
{
	if (!_ioh) {
		return false;
	}

	if (!_ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress ||		// In this case, "VirtualAddress" is actually a file offset.
		fseek(f, _ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress, SEEK_SET))	{
		return true;	// Unsigned binary
	}

	unsigned int remaining_bytes = _ioh->directories[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
	unsigned int header_size = sizeof(boost::uint32_t) + 2*sizeof(boost::uint16_t);
	while (remaining_bytes > header_size)
	{
		pwin_certificate cert = pwin_certificate(new win_certificate);
		memset(cert.get(), 0, header_size);
		if (header_size != fread(cert.get(), 1, header_size, f))
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
			PRINT_WARNING << "The WIN_CERTIFICATE appears to be invalid." << std::endl;
			return true; // Recoverable error.
		}


		try {
			cert->Certificate.resize(cert->Length);
		}
		catch (const std::exception& e)
		{
			PRINT_ERROR << "Failed to allocate enough space for a certificate! (" << e.what() << ")"
				<< DEBUG_INFO_INSIDEPE << std::endl;
			cert->Certificate.resize(0);
			return false;
		}

		if (cert->Length < remaining_bytes ||
			cert->Length - header_size != fread(&(cert->Certificate[0]), 1, cert->Length - header_size, f))
		{
			PRINT_ERROR << "Could not read a WIN_CERTIFICATE's data." << std::endl;
			return false;
		}
		remaining_bytes -= cert->Length;
		_certificates.push_back(cert);

		// The certificates start on 8-byte aligned addresses
		unsigned int padding = cert->Length % 8;
		if (padding && remaining_bytes)
		{
			fseek(f, padding, SEEK_CUR);
			remaining_bytes -= padding;
		}
	}

	return true;
}

// ----------------------------------------------------------------------------

// Provide a destructor for the shared_ptr.
void delete_manape_module_data(manape_data* data)
{
	if (data->sections != NULL) {
		free(data->sections);
	}
}

boost::shared_ptr<manape_data> PE::create_manape_module_data() const
{
	boost::shared_ptr<manape_data> res(new manape_data, delete_manape_module_data);
	res->entrypoint = _ioh->AddressOfEntryPoint;
	res->number_of_sections = _sections.size();
	res->sections = (manape_section*) malloc(res->number_of_sections * sizeof(manape_section));
	if (res->sections != NULL)
	{
		for (boost::uint32_t i = 0 ; i < res->number_of_sections ; ++i)
		{
			res->sections[i].section_start = _sections[i]->get_pointer_to_raw_data();
			res->sections[i].section_size = _sections[i]->get_size_of_raw_data();
		}
	}
	else
	{
		PRINT_WARNING << "Not enough memory to allocate data for the MANAPE module!" << std::endl;
		res->number_of_sections = 0;
	}
	return res;
}

} // !namespace sg
