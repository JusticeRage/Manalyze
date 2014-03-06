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
	

	_initialized = true;

	END:
	fclose(f);
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

bool PE::_parse_image_optional_header(FILE* f)
{
	memset(&_ioh, 0, sizeof(_ioh));

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

	return true;
}

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
	sink << "NumberOfRvaAndSizes\t\t" << _ioh.NumberOfRvaAndSizes << std::endl;
}

} // !namespace sg
