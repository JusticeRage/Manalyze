#include "pe.h"

namespace sg 
{

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
	std::vector<std::string> dlls = get_imported_dlls();
	for (std::vector<std::string>::iterator it = dlls.begin() ; it != dlls.end() ; ++it)
	{
		sink << *it << std::endl;
		std::vector<std::string> functions = get_imported_functions(*it);
		for (std::vector<std::string>::iterator it2 = functions.begin() ; it2 != functions.end() ; ++it2)
		{
			sink << "\t" << (*it2) << std::endl;
		}
		
	}

	sink << std::endl;
}

void PE::dump_exports(std::ostream& sink) const
{
	if (!_initialized) {
		return;
	}

	sink << "EXPORTS:" << std::endl << "--------" << std::endl << std::endl;
	for (std::vector<pexported_function>::const_iterator it = _exports.begin() ; it != _exports.end() ; ++it)
	{
		sink << std::dec << (*it)->Ordinal << "\t0x" << std::hex << (*it)->Address;
		if ((*it)->Name != "") {
			sink <<  "\t" << (*it)->Name;
		}
		if ((*it)->ForwardName != "") {
			sink <<  " -> " << (*it)->ForwardName;
		}
		sink << std::endl;
	}
}


} // !namespace sg