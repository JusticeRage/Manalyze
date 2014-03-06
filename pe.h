#ifndef _PE_H_
#define _PE_H_

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <algorithm>

#include <string>
#include <vector>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>

#include "nt_values.h"

namespace sg {

typedef struct dos_header_t
{
    boost::uint8_t  e_magic[2];
    boost::uint16_t e_cblp;
    boost::uint16_t e_cp;
    boost::uint16_t e_crlc;
    boost::uint16_t e_cparhdr;
    boost::uint16_t e_minalloc;
    boost::uint16_t e_maxalloc;
    boost::uint16_t e_ss;
    boost::uint16_t e_sp;
    boost::uint16_t e_csum;
    boost::uint16_t e_ip;
    boost::uint16_t e_cs;
    boost::uint16_t e_lfarlc;
    boost::uint16_t e_ovno;
    boost::uint16_t e_res[4];
    boost::uint16_t e_oemid;
    boost::uint16_t e_oeminfo;
    boost::uint16_t e_res2[10];
    boost::uint32_t e_lfanew;
} dos_header;

typedef struct pe_header_t
{
	boost::uint8_t  Signature[4];
	boost::uint16_t Machine;
	boost::uint16_t NumberofSections;
	boost::uint32_t TimeDateStamp;
	boost::uint32_t PointerToSymbolTable;
	boost::uint32_t NumberOfSymbols;
	boost::uint16_t SizeOfOptionalHeader;
	boost::uint16_t Characteristics;
} pe_header;

typedef struct image_data_directory_t
{
	boost::uint32_t VirtualAddress;
	boost::uint32_t Size;
} image_data_directory;

typedef struct image_optional_header_t
{
	boost::uint16_t Magic;
	boost::uint8_t  MajorLinkerVersion;
	boost::uint8_t  MinorLinkerVersion;
	boost::uint32_t SizeOfCode;
	boost::uint32_t SizeOfInitializedData;
	boost::uint32_t SizeOfUninitializedData;
	boost::uint32_t AddressOfEntryPoint;
	boost::uint32_t BaseOfCode;
	boost::uint32_t BaseOfData;
	boost::uint64_t ImageBase;
	boost::uint32_t SectionAlignment;
	boost::uint32_t FileAlignment;
	boost::uint16_t MajorOperatingSystemVersion;
	boost::uint16_t MinorOperatingSystemVersion;
	boost::uint16_t MajorImageVersion;
	boost::uint16_t MinorImageVersion;
	boost::uint16_t MajorSubsystemVersion;
	boost::uint16_t MinorSubsystemVersion;
	boost::uint32_t Win32VersionValue;
	boost::uint32_t SizeOfImage;
	boost::uint32_t SizeOfHeaders;
	boost::uint32_t Checksum;
	boost::uint16_t Subsystem;
	boost::uint16_t DllCharacteristics;
	boost::uint64_t SizeofStackReserve;
	boost::uint64_t SizeofStackCommit;
	boost::uint64_t SizeofHeapReserve;
	boost::uint64_t SizeofHeapCommit;
	boost::uint32_t LoaderFlags;
	boost::uint32_t NumberOfRvaAndSizes;
	image_data_directory directories[0x10];
} image_optional_header;

typedef struct simage_section_header_t
{
	boost::uint8_t  Name[8];
	boost::uint32_t VirtualSize;
	boost::uint32_t VirtualAddress;
	boost::uint32_t SizeOfRawData;
	boost::uint32_t PointerToRawData;
	boost::uint32_t PointerToRelocations;
	boost::uint32_t PointerToLineNumbers;
	boost::uint16_t NumberOfRelocations;
	boost::uint16_t NumberOfLineNumbers;
	boost::uint32_t Characteristics;
} image_section_header;
typedef boost::shared_ptr<image_section_header> pimage_section_header;

class PE
{

public:
	PE(const std::string& path);

	size_t get_filesize();

    std::string get_path()  const { return _path; }

	void dump_dos_header(std::ostream& sink = std::cout) const;
	void dump_pe_header(std::ostream& sink = std::cout) const;
	void dump_image_optional_header(std::ostream& sink = std::cout) const;
	void dump_section_table(std::ostream& sink = std::cout) const;

private:
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

	std::string							_path;
    bool								_initialized;
    size_t								_size;

	// Fields related to the PE structure.
	dos_header							_h_dos;
	pe_header							_h_pe;
	image_optional_header				_ioh;
	std::vector<pimage_section_header>	_section_table;
};


} /* !namespace sg */

#endif /* !_PE_H_ */
