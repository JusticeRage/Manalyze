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

#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>

namespace mana
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

// ----------------------------------------------------------------------------

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

// ----------------------------------------------------------------------------

typedef struct image_data_directory_t
{
	boost::uint32_t VirtualAddress;
	boost::uint32_t Size;
} image_data_directory;

// ----------------------------------------------------------------------------

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

// ----------------------------------------------------------------------------

typedef struct image_section_header_t
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

// ----------------------------------------------------------------------------

typedef struct image_import_descriptor_t
{
	boost::uint32_t OriginalFirstThunk;
	boost::uint32_t TimeDateStamp;
	boost::uint32_t ForwarderChain;
	boost::uint32_t	Name;
	boost::uint32_t FirstThunk;
} image_import_descriptor;
typedef boost::shared_ptr<image_import_descriptor> pimage_import_descriptor;

// ----------------------------------------------------------------------------

// For convenience, this structure has been merged with the associated Hint/Name table
typedef struct import_lookup_table_t
{
	boost::uint64_t	AddressOfData;
	boost::uint16_t	Hint;
	std::string		Name;
} import_lookup_table;
typedef boost::shared_ptr<import_lookup_table> pimport_lookup_table;

// ----------------------------------------------------------------------------

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
	std::string		NameStr; // Non-standard!
} image_export_directory;
typedef boost::shared_ptr<image_export_directory> pexport_image_directory;

// ----------------------------------------------------------------------------

typedef struct coff_symbol_t
{
	boost::uint8_t  Name[8];
	boost::uint32_t	Value;
	boost::uint16_t	SectionNumber;
	boost::uint16_t	Type;
	boost::uint8_t	StorageClass;
	boost::uint8_t	NumberOfAuxSymbols;
} coff_symbol;
typedef boost::shared_ptr<coff_symbol> pcoff_symbol;

// ----------------------------------------------------------------------------

// Not a standard Windows structure, but useful when it comes to representing exports.
typedef struct exported_function_t
{
	boost::uint32_t Ordinal;
	boost::uint32_t Address;
	std::string		Name;
	std::string		ForwardName;
} exported_function;
typedef boost::shared_ptr<exported_function> pexported_function;

// ----------------------------------------------------------------------------

typedef struct image_resource_directory_entry_t
{
	boost::uint32_t	NameOrId;
	boost::uint32_t OffsetToData;
	std::string		NameStr; // Non-standard!
} image_resource_directory_entry;
typedef boost::shared_ptr<image_resource_directory_entry> pimage_resource_directory_entry;

// ----------------------------------------------------------------------------

typedef struct image_resource_directory_t
{
	boost::uint32_t	Characteristics;
	boost::uint32_t TimeDateStamp;
	boost::uint16_t	MajorVersion;
	boost::uint16_t	minorVersion;
	boost::uint16_t	NumberOfNamedEntries;
	boost::uint16_t	NumberOfIdEntries;
	std::vector<pimage_resource_directory_entry> Entries;
} image_resource_directory;
typedef boost::shared_ptr<image_resource_directory> pimage_resource_directory;

// ----------------------------------------------------------------------------

typedef struct image_resource_data_entry_t
{
	boost::uint32_t	OffsetToData;
	boost::uint32_t	Size;
	boost::uint32_t	Codepage;
	boost::uint32_t	Reserved;
} image_resource_data_entry;

// ----------------------------------------------------------------------------

typedef struct group_icon_directory_entry_t
{
	boost::uint8_t	Width;
	boost::uint8_t	Height;
	boost::uint8_t	ColorCount;
	boost::uint8_t	Reserved;
	boost::uint16_t	Planes;
	boost::uint16_t	BitCount;
	boost::uint32_t	BytesInRes;

	// /!\ WARNING: This field is a boost::uint16_t in the specification
	// I switched it back to a boost::uint32_t to match the ICO file structure.
	boost::uint32_t	Id;
} group_icon_directory_entry;
typedef boost::shared_ptr<group_icon_directory_entry> pgroup_icon_directory_entry;

// ----------------------------------------------------------------------------

typedef struct group_icon_directory_t
{
	boost::uint16_t	Reserved;
	boost::uint16_t	Type;
	boost::uint16_t	Count;
	std::vector<pgroup_icon_directory_entry> Entries;
} group_icon_directory;
typedef boost::shared_ptr<group_icon_directory> pgroup_icon_directory;

// ----------------------------------------------------------------------------

// Not a standard structure. Bitmaps stored as resources don't have a header.
// This represents the reconstructed header, followed by the resource data.
#pragma pack (push, 1)
typedef struct bitmap_t
{
	boost::uint8_t	Magic[2];
	boost::uint32_t Size;
	boost::uint16_t Reserved1;
	boost::uint16_t Reserved2;
	boost::uint32_t OffsetToData;
	std::vector<boost::uint8_t> data;
} bitmap;
#pragma pack (pop)
typedef boost::shared_ptr<bitmap_t> pbitmap;

// ----------------------------------------------------------------------------

typedef struct vs_fixed_file_info_t
{
	boost::uint32_t	Signature;
	boost::uint32_t	StructVersion;
	boost::uint32_t	FileVersionMS;
	boost::uint32_t	FileVersionLS;
	boost::uint32_t	ProductVersionMS;
	boost::uint32_t	ProductVersionLS;
	boost::uint32_t	FileFlagsMask;
	boost::uint32_t	FileFlags;
	boost::uint32_t	FileOs;
	boost::uint32_t	FileType;
	boost::uint32_t	FileSubtype;
	boost::uint32_t	FileDateMS;
	boost::uint32_t	FileDateLS;
} fixed_file_info;
typedef boost::shared_ptr<fixed_file_info> pfixed_file_info;

// ----------------------------------------------------------------------------

// Non-standard enum. This sequence does return a lot, though, so it was
// worth putting it in a separate structure.
typedef struct vs_version_info_header_t
{
	boost::uint16_t		Length;
	boost::uint16_t		ValueLength;
	boost::uint16_t		Type;
	std::string			Key;
} vs_version_info_header;
typedef boost::shared_ptr<vs_version_info_header> pvs_version_info_header;

// ----------------------------------------------------------------------------

// Non-standard enum. The last two field have been added for convenience.
typedef std::pair<std::string, std::string> string_pair;
typedef boost::shared_ptr<string_pair> ppair;
typedef struct vs_version_info_t
{
	vs_version_info_header	Header;
	pfixed_file_info		Value;
	std::string				Language;
	std::vector<ppair>		StringTable;
} version_info;
typedef boost::shared_ptr<vs_version_info_t> pversion_info;

// ----------------------------------------------------------------------------

// Non-standard enum. No information regarding underlying structures is kept.
// If you need a more complete parsing here, let me know.
typedef struct debug_directory_entry_t
{
	boost::uint32_t	Characteristics;
	boost::uint32_t	TimeDateStamp;
	boost::uint16_t	MajorVersion;
	boost::uint16_t	MinorVersion;
	boost::uint32_t	Type;
	boost::uint32_t	SizeofData;
	boost::uint32_t	AddressOfRawData;
	boost::uint32_t	PointerToRawData;
	std::string		Filename; // Non-standard!
} debug_directory_entry;
typedef boost::shared_ptr<debug_directory_entry> pdebug_directory_entry;

// ----------------------------------------------------------------------------

typedef struct pdb_info_t
{
	boost::uint32_t	Signature;
	boost::uint8_t	Guid[16];
	boost::uint32_t	Age;
	std::string		PdbFileName;
} pdb_info;

// ----------------------------------------------------------------------------

typedef struct image_base_relocation_t
{
	boost::uint32_t					PageRVA;
	boost::uint32_t					BlockSize;
	std::vector<boost::uint16_t>	TypesOffsets; // Non-standard!
} image_base_relocation;
typedef boost::shared_ptr<image_base_relocation_t> pimage_base_relocation;

// ----------------------------------------------------------------------------

typedef struct image_debug_misc_t
{
	boost::uint32_t	DataType;
	boost::uint32_t	Length;
	boost::uint8_t	Unicode;
	boost::uint8_t	Reserved[3];
	std::string		DbgFile;
} image_debug_misc;

// ----------------------------------------------------------------------------

typedef struct image_tls_directory_t
{
	boost::uint64_t					StartAddressOfRawData;
	boost::uint64_t					EndAddressOfRawData;
	boost::uint64_t					AddressOfIndex;
	boost::uint64_t					AddressOfCallbacks;
	boost::uint32_t					SizeOfZeroFill;
	boost::uint32_t					Characteristics;
	std::vector<boost::uint64_t>	Callbacks;	// Non-standard!
} image_tls_directory;

// ----------------------------------------------------------------------------

typedef struct win_certificate_t
{
	boost::uint32_t				Length;
	boost::uint16_t				Revision;
	boost::uint16_t				CertificateType;
	std::vector<boost::uint8_t>	Certificate;
} win_certificate;
typedef boost::shared_ptr<win_certificate> pwin_certificate;

// ----------------------------------------------------------------------------

typedef struct image_load_config_code_integrity_t
{
	boost::uint16_t	Flags;
	boost::uint16_t Catalog;
	boost::uint32_t	CatalogOffset;
	boost::uint32_t	Reserved;
} image_load_config_code_integrity;

// ----------------------------------------------------------------------------

typedef struct image_load_config_directory_t
{
	boost::uint32_t	Size;
	boost::uint32_t	TimeDateStamp;
	boost::uint16_t	MajorVersion;
	boost::uint16_t	MinorVersion;
	boost::uint32_t GlobalFlagsClear;
	boost::uint32_t GlobalFlagsSet;
	boost::uint32_t CriticalSectionDefaultTimeout;
	boost::uint64_t DeCommitFreeBlockThreshold;
	boost::uint64_t DeCommitTotalFreeThreshold;
	boost::uint64_t LockPrefixTable;
	boost::uint64_t MaximumAllocationSize;
	boost::uint64_t VirtualMemoryThreshold;
	boost::uint64_t ProcessAffinityMask;
	boost::uint32_t ProcessHeapFlags;
	boost::uint16_t CSDVersion;
	boost::uint16_t Reserved1;
	boost::uint64_t EditList;
	boost::uint64_t SecurityCookie;
	boost::uint64_t SEHandlerTable;
	boost::uint64_t SEHandlerCount;
	boost::uint64_t GuardCFCheckFunctionPointer;
	boost::uint64_t GuardCFDispatchFunctionPointer;
	boost::uint64_t GuardCFFunctionTable;
	boost::uint64_t GuardCFFunctionCount;
	boost::uint32_t GuardFlags;
	image_load_config_code_integrity CodeIntegrity;
	boost::uint64_t GuardAddressTakenIatEntryTable;
	boost::uint64_t GuardAddressTakenIatEntryCount;
	boost::uint64_t	GuardLongJumpTargetTable;
	boost::uint64_t GuardLongJumpTargetCount;
} image_load_config_directory;

// ----------------------------------------------------------------------------

typedef struct delay_load_directory_table_t
{
    boost::uint32_t Attributes;
    boost::uint32_t Name;
    boost::uint32_t ModuleHandle;
    boost::uint32_t DelayImportAddressTable;
    boost::uint32_t DelayImportNameTable;
    boost::uint32_t BoundDelayImportTable;
    boost::uint32_t UnloadDelayImportTable;
    boost::uint32_t TimeStamp;
	std::string		NameStr; // Non-standard!
} delay_load_directory_table;

// ----------------------------------------------------------------------------

typedef struct rich_header_t
{
	boost::uint32_t xor_key;
	boost::uint32_t file_offset;  // We keep a reference of where the structure starts.
	// Structure : id, product_id, count
	std::vector<std::tuple<boost::uint16_t, boost::uint16_t, boost::uint32_t> > values;
} rich_header;

} // !namespace mana
