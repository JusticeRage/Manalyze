#ifndef _PE_STRUCTS_H_
#define _PE_STRUCTS_H_

#include <vector>
#include <string>

#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>

namespace sg 
{

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

// A field has been added at the end of the structure to keep the Name of the library.
// The original Name field only contains a RVA, which is impractical.
typedef struct image_import_descriptor_t
{
	boost::uint32_t OriginalFirstThunk;
	boost::uint32_t TimeDateStamp;
	boost::uint32_t ForwarderChain;
	boost::uint32_t	Name;
	boost::uint32_t FirstThunk;
	std::string		NameStr; // Non-standard!
} image_import_descriptor;
typedef boost::shared_ptr<image_import_descriptor> pimage_import_descriptor;

// For convenience, this structure has been merged with the associated Hint/Name table
typedef struct import_lookup_table_t
{
	boost::uint64_t	AddressOfData;
	boost::uint16_t	Hint;
	std::string		Name;
} import_lookup_table;
typedef boost::shared_ptr<import_lookup_table> pimport_lookup_table;

// This typedef isn't a Windows standard, but I find this representation useful when describing
// all the imports related to a single DLL.
typedef std::pair<pimage_import_descriptor, std::vector<pimport_lookup_table> > image_library_descriptor;
typedef boost::shared_ptr<image_library_descriptor> pimage_library_descriptor;

// A field has been added at the end of the structure to keep the Name of the library.
// The original Name field only contains a RVA, which is impractical.
typedef struct image_export_directory_t
{
	boost::uint32_t Characteristics;
	boost::uint32_t TimeDateStamp;
	boost::uint16_t MajorVersion;
	boost::uint16_t MinorVersion;
	boost::uint32_t Name;
	boost::uint32_t Base;
	boost::uint32_t NumberOfFunctions;
	boost::uint32_t NumberOfNames;
	boost::uint32_t AddressOfFunctions;
	boost::uint32_t AddressOfNames;
	boost::uint32_t AddressOfNameOrdinals;
	std::string		NameStr;
} image_export_directory;
typedef boost::shared_ptr<image_export_directory> pexport_image_directory;

// Not a standard Windows structure, but useful when it comes to representing exports.
typedef struct exported_function_t
{
	boost::uint32_t Ordinal;
	boost::uint32_t Address;
	std::string		Name;
	std::string		ForwardName;
} exported_function;
typedef boost::shared_ptr<exported_function> pexported_function;

} // !namespace sg

#endif // !_PE_STRUCTS_H_