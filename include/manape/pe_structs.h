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

#include <cstdint>
#include <memory>

namespace mana
{

typedef struct dos_header_t
{
	std::uint8_t  e_magic[2];
	std::uint16_t e_cblp;
	std::uint16_t e_cp;
	std::uint16_t e_crlc;
	std::uint16_t e_cparhdr;
	std::uint16_t e_minalloc;
	std::uint16_t e_maxalloc;
	std::uint16_t e_ss;
	std::uint16_t e_sp;
	std::uint16_t e_csum;
	std::uint16_t e_ip;
	std::uint16_t e_cs;
	std::uint16_t e_lfarlc;
	std::uint16_t e_ovno;
	std::uint16_t e_res[4];
	std::uint16_t e_oemid;
	std::uint16_t e_oeminfo;
	std::uint16_t e_res2[10];
	std::uint32_t e_lfanew;
} dos_header;

// ----------------------------------------------------------------------------

typedef struct pe_header_t
{
	std::uint8_t  Signature[4];
	std::uint16_t Machine;
	std::uint16_t NumberofSections;
	std::uint32_t TimeDateStamp;
	std::uint32_t PointerToSymbolTable;
	std::uint32_t NumberOfSymbols;
	std::uint16_t SizeOfOptionalHeader;
	std::uint16_t Characteristics;
} pe_header;

// ----------------------------------------------------------------------------

typedef struct image_data_directory_t
{
	std::uint32_t VirtualAddress;
	std::uint32_t Size;
} image_data_directory;

// ----------------------------------------------------------------------------

typedef struct image_optional_header_t
{
	std::uint16_t Magic;
	std::uint8_t  MajorLinkerVersion;
	std::uint8_t  MinorLinkerVersion;
	std::uint32_t SizeOfCode;
	std::uint32_t SizeOfInitializedData;
	std::uint32_t SizeOfUninitializedData;
	std::uint32_t AddressOfEntryPoint;
	std::uint32_t BaseOfCode;
	std::uint32_t BaseOfData;
	std::uint64_t ImageBase;
	std::uint32_t SectionAlignment;
	std::uint32_t FileAlignment;
	std::uint16_t MajorOperatingSystemVersion;
	std::uint16_t MinorOperatingSystemVersion;
	std::uint16_t MajorImageVersion;
	std::uint16_t MinorImageVersion;
	std::uint16_t MajorSubsystemVersion;
	std::uint16_t MinorSubsystemVersion;
	std::uint32_t Win32VersionValue;
	std::uint32_t SizeOfImage;
	std::uint32_t SizeOfHeaders;
	std::uint32_t Checksum;
	std::uint16_t Subsystem;
	std::uint16_t DllCharacteristics;
	std::uint64_t SizeofStackReserve;
	std::uint64_t SizeofStackCommit;
	std::uint64_t SizeofHeapReserve;
	std::uint64_t SizeofHeapCommit;
	std::uint32_t LoaderFlags;
	std::uint32_t NumberOfRvaAndSizes;
	image_data_directory directories[0x10];
} image_optional_header;

// ----------------------------------------------------------------------------

typedef struct image_section_header_t
{
	std::uint8_t  Name[8];
	std::uint32_t VirtualSize;
	std::uint32_t VirtualAddress;
	std::uint32_t SizeOfRawData;
	std::uint32_t PointerToRawData;
	std::uint32_t PointerToRelocations;
	std::uint32_t PointerToLineNumbers;
	std::uint16_t NumberOfRelocations;
	std::uint16_t NumberOfLineNumbers;
	std::uint32_t Characteristics;
} image_section_header;
typedef std::shared_ptr<image_section_header> pimage_section_header;

// ----------------------------------------------------------------------------

typedef struct image_import_descriptor_t
{
	std::uint32_t OriginalFirstThunk;
	std::uint32_t TimeDateStamp;
	std::uint32_t ForwarderChain;
	std::uint32_t	Name;
	std::uint32_t FirstThunk;
} image_import_descriptor;
typedef std::shared_ptr<image_import_descriptor> pimage_import_descriptor;

// ----------------------------------------------------------------------------

// For convenience, this structure has been merged with the associated Hint/Name table
typedef struct import_lookup_table_t
{
	std::uint64_t	AddressOfData;
	std::uint16_t	Hint;
	std::string		Name;
} import_lookup_table;
typedef std::shared_ptr<import_lookup_table> pimport_lookup_table;

// ----------------------------------------------------------------------------

// A field has been added at the end of the structure to keep the Name of the library.
// The original Name field only contains a RVA, which is impractical.
typedef struct image_export_directory_t
{
	std::uint32_t Characteristics;
	std::uint32_t TimeDateStamp;
	std::uint16_t MajorVersion;
	std::uint16_t MinorVersion;
	std::uint32_t Name;
	std::uint32_t Base;
	std::uint32_t NumberOfFunctions;
	std::uint32_t NumberOfNames;
	std::uint32_t AddressOfFunctions;
	std::uint32_t AddressOfNames;
	std::uint32_t AddressOfNameOrdinals;
	std::string		NameStr; // Non-standard!
} image_export_directory;
typedef std::shared_ptr<image_export_directory> pexport_image_directory;

// ----------------------------------------------------------------------------

typedef struct coff_symbol_t
{
	std::uint8_t  Name[8];
	std::uint32_t	Value;
	std::uint16_t	SectionNumber;
	std::uint16_t	Type;
	std::uint8_t	StorageClass;
	std::uint8_t	NumberOfAuxSymbols;
} coff_symbol;
typedef std::shared_ptr<coff_symbol> pcoff_symbol;

// ----------------------------------------------------------------------------

// Not a standard Windows structure, but useful when it comes to representing exports.
typedef struct exported_function_t
{
	std::uint32_t Ordinal;
	std::uint32_t Address;
	std::string		Name;
	std::string		ForwardName;
} exported_function;
typedef std::shared_ptr<exported_function> pexported_function;

// ----------------------------------------------------------------------------

typedef struct image_resource_directory_entry_t
{
	std::uint32_t	NameOrId;
	std::uint32_t OffsetToData;
	std::string		NameStr; // Non-standard!
} image_resource_directory_entry;
typedef std::shared_ptr<image_resource_directory_entry> pimage_resource_directory_entry;

// ----------------------------------------------------------------------------

typedef struct image_resource_directory_t
{
	std::uint32_t	Characteristics;
	std::uint32_t TimeDateStamp;
	std::uint16_t	MajorVersion;
	std::uint16_t	minorVersion;
	std::uint16_t	NumberOfNamedEntries;
	std::uint16_t	NumberOfIdEntries;
	std::vector<pimage_resource_directory_entry> Entries;
} image_resource_directory;
typedef std::shared_ptr<image_resource_directory> pimage_resource_directory;

// ----------------------------------------------------------------------------

typedef struct image_resource_data_entry_t
{
	std::uint32_t	OffsetToData;
	std::uint32_t	Size;
	std::uint32_t	Codepage;
	std::uint32_t	Reserved;
} image_resource_data_entry;

// ----------------------------------------------------------------------------

typedef struct group_icon_directory_entry_t
{
	std::uint8_t	Width;
	std::uint8_t	Height;
	std::uint8_t	ColorCount;
	std::uint8_t	Reserved;
	std::uint16_t	Planes;
	std::uint16_t	BitCount;
	std::uint32_t	BytesInRes;

	// /!\ WARNING: This field is a std::uint16_t in the specification
	// I switched it back to a std::uint32_t to match the ICO file structure.
	std::uint32_t	Id;
} group_icon_directory_entry;
typedef std::shared_ptr<group_icon_directory_entry> pgroup_icon_directory_entry;

// ----------------------------------------------------------------------------

typedef struct group_icon_directory_t
{
	std::uint16_t	Reserved;
	std::uint16_t	Type;
	std::uint16_t	Count;
	std::vector<pgroup_icon_directory_entry> Entries;
} group_icon_directory;
typedef std::shared_ptr<group_icon_directory> pgroup_icon_directory;

// ----------------------------------------------------------------------------

// Not a standard structure. Bitmaps stored as resources don't have a header.
// This represents the reconstructed header, followed by the resource data.
#pragma pack (push, 1)
typedef struct bitmap_t
{
	std::uint8_t	Magic[2];
	std::uint32_t Size;
	std::uint16_t Reserved1;
	std::uint16_t Reserved2;
	std::uint32_t OffsetToData;
	std::vector<std::uint8_t> data;
} bitmap;
#pragma pack (pop)
typedef std::shared_ptr<bitmap_t> pbitmap;

// ----------------------------------------------------------------------------

typedef struct vs_fixed_file_info_t
{
	std::uint32_t	Signature;
	std::uint32_t	StructVersion;
	std::uint32_t	FileVersionMS;
	std::uint32_t	FileVersionLS;
	std::uint32_t	ProductVersionMS;
	std::uint32_t	ProductVersionLS;
	std::uint32_t	FileFlagsMask;
	std::uint32_t	FileFlags;
	std::uint32_t	FileOs;
	std::uint32_t	FileType;
	std::uint32_t	FileSubtype;
	std::uint32_t	FileDateMS;
	std::uint32_t	FileDateLS;
} fixed_file_info;
typedef std::shared_ptr<fixed_file_info> pfixed_file_info;

// ----------------------------------------------------------------------------

// Non-standard enum. This sequence does return a lot, though, so it was
// worth putting it in a separate structure.
typedef struct vs_version_info_header_t
{
	std::uint16_t		Length;
	std::uint16_t		ValueLength;
	std::uint16_t		Type;
	std::string			Key;
} vs_version_info_header;
typedef std::shared_ptr<vs_version_info_header> pvs_version_info_header;

// ----------------------------------------------------------------------------

// Non-standard enum. The last two field have been added for convenience.
typedef std::pair<std::string, std::string> string_pair;
typedef std::shared_ptr<string_pair> ppair;
typedef struct vs_version_info_t
{
	vs_version_info_header	Header;
	pfixed_file_info		Value;
	std::string				Language;
	std::vector<ppair>		StringTable;
} version_info;
typedef std::shared_ptr<vs_version_info_t> pversion_info;

// ----------------------------------------------------------------------------

// Non-standard enum. No information regarding underlying structures is kept.
// If you need a more complete parsing here, let me know.
typedef struct debug_directory_entry_t
{
	std::uint32_t	Characteristics;
	std::uint32_t	TimeDateStamp;
	std::uint16_t	MajorVersion;
	std::uint16_t	MinorVersion;
	std::uint32_t	Type;
	std::uint32_t	SizeofData;
	std::uint32_t	AddressOfRawData;
	std::uint32_t	PointerToRawData;
	std::string		Filename; // Non-standard!
} debug_directory_entry;
typedef std::shared_ptr<debug_directory_entry> pdebug_directory_entry;

// ----------------------------------------------------------------------------

typedef struct pdb_info_t
{
	std::uint32_t	Signature;
	std::uint8_t	Guid[16];
	std::uint32_t	Age;
	std::string		PdbFileName;
} pdb_info;

// ----------------------------------------------------------------------------

typedef struct image_base_relocation_t
{
	std::uint32_t					PageRVA;
	std::uint32_t					BlockSize;
	std::vector<std::uint16_t>	TypesOffsets; // Non-standard!
} image_base_relocation;
typedef std::shared_ptr<image_base_relocation_t> pimage_base_relocation;

// ----------------------------------------------------------------------------

typedef struct image_debug_misc_t
{
	std::uint32_t	DataType;
	std::uint32_t	Length;
	std::uint8_t	Unicode;
	std::uint8_t	Reserved[3];
	std::string		DbgFile;
} image_debug_misc;

// ----------------------------------------------------------------------------

typedef struct image_tls_directory_t
{
	std::uint64_t					StartAddressOfRawData;
	std::uint64_t					EndAddressOfRawData;
	std::uint64_t					AddressOfIndex;
	std::uint64_t					AddressOfCallbacks;
	std::uint32_t					SizeOfZeroFill;
	std::uint32_t					Characteristics;
	std::vector<std::uint64_t>	Callbacks;	// Non-standard!
} image_tls_directory;

// ----------------------------------------------------------------------------

typedef struct win_certificate_t
{
	std::uint32_t				Length;
	std::uint16_t				Revision;
	std::uint16_t				CertificateType;
	std::vector<std::uint8_t>	Certificate;
} win_certificate;
typedef std::shared_ptr<win_certificate> pwin_certificate;

// ----------------------------------------------------------------------------

typedef struct image_load_config_code_integrity_t
{
	std::uint16_t	Flags;
	std::uint16_t Catalog;
	std::uint32_t	CatalogOffset;
	std::uint32_t	Reserved;
} image_load_config_code_integrity;

// ----------------------------------------------------------------------------

typedef struct image_load_config_directory_t
{
	std::uint32_t	Size;
	std::uint32_t	TimeDateStamp;
	std::uint16_t	MajorVersion;
	std::uint16_t	MinorVersion;
	std::uint32_t GlobalFlagsClear;
	std::uint32_t GlobalFlagsSet;
	std::uint32_t CriticalSectionDefaultTimeout;
	std::uint64_t DeCommitFreeBlockThreshold;
	std::uint64_t DeCommitTotalFreeThreshold;
	std::uint64_t LockPrefixTable;
	std::uint64_t MaximumAllocationSize;
	std::uint64_t VirtualMemoryThreshold;
	std::uint64_t ProcessAffinityMask;
	std::uint32_t ProcessHeapFlags;
	std::uint16_t CSDVersion;
	std::uint16_t Reserved1;
	std::uint64_t EditList;
	std::uint64_t SecurityCookie;
	std::uint64_t SEHandlerTable;
	std::uint64_t SEHandlerCount;
	std::uint64_t GuardCFCheckFunctionPointer;
	std::uint64_t GuardCFDispatchFunctionPointer;
	std::uint64_t GuardCFFunctionTable;
	std::uint64_t GuardCFFunctionCount;
	std::uint32_t GuardFlags;
	image_load_config_code_integrity CodeIntegrity;
	std::uint64_t GuardAddressTakenIatEntryTable;
	std::uint64_t GuardAddressTakenIatEntryCount;
	std::uint64_t	GuardLongJumpTargetTable;
	std::uint64_t GuardLongJumpTargetCount;
} image_load_config_directory;

// ----------------------------------------------------------------------------

typedef struct delay_load_directory_table_t
{
    std::uint32_t Attributes;
    std::uint32_t Name;
    std::uint32_t ModuleHandle;
    std::uint32_t DelayImportAddressTable;
    std::uint32_t DelayImportNameTable;
    std::uint32_t BoundDelayImportTable;
    std::uint32_t UnloadDelayImportTable;
    std::uint32_t TimeStamp;
	std::string		NameStr; // Non-standard!
} delay_load_directory_table;

// ----------------------------------------------------------------------------

typedef struct rich_header_t
{
	std::uint32_t xor_key;
	std::uint32_t file_offset;  // We keep a reference of where the structure starts.
	// Structure : id, product_id, count
	std::vector<std::tuple<std::uint16_t, std::uint16_t, std::uint32_t> > values;
} rich_header;

} // !namespace mana
