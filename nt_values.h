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

#ifndef  _NT_VALUES_H_
# define _NT_VALUES_H_

#include <string>
#include <map>
#include <vector>
#include <boost/assign.hpp>

// Directory Entries - copied from WinNT.h
// There is no need for a map for this one: we won't have to translate the values back to their names.
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

namespace nt {

typedef std::map<std::string, int> flag_dict;

static flag_dict PE_CHARACTERISTICS = 
	boost::assign::map_list_of ("IMAGE_FILE_RELOCS_STRIPPED",			0x0001) 
							   ("IMAGE_FILE_EXECUTABLE_IMAGE",			0x0002)
							   ("IMAGE_FILE_LINE_NUMS_STRIPPED",		0x0004)
							   ("IMAGE_FILE_LOCAL_SYMS_STRIPPED",		0x0008)
							   ("IMAGE_FILE_AGGRESIVE_WS_TRIM",			0x0010)
							   ("IMAGE_FILE_LARGE_ADDRESS_AWARE",		0x0020)
							   ("IMAGE_FILE_BYTES_REVERSED_LO",			0x0080)
							   ("IMAGE_FILE_32BIT_MACHINE",				0x0100)
							   ("IMAGE_FILE_DEBUG_STRIPPED",			0x0200)
							   ("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",	0x0400)
							   ("IMAGE_FILE_NET_RUN_FROM_SWAP",			0x0800)
							   ("IMAGE_FILE_SYSTEM",					0x1000)
							   ("IMAGE_FILE_DLL",						0x2000)
							   ("IMAGE_FILE_UP_SYSTEM_ONLY",			0x4000)
							   ("IMAGE_FILE_BYTES_REVERSED_HI",			0x8000);

static flag_dict MACHINE_TYPES =
	boost::assign::map_list_of ("IMAGE_FILE_MACHINE_UNKNOWN",			0)
							   ("IMAGE_FILE_MACHINE_I386",				0x014c)
							   ("IMAGE_FILE_MACHINE_R3000",				0x0162)
							   ("IMAGE_FILE_MACHINE_R4000",				0x0166)
							   ("IMAGE_FILE_MACHINE_R10000",			0x0168)
							   ("IMAGE_FILE_MACHINE_WCEMIPSV2",			0x0169)
							   ("IMAGE_FILE_MACHINE_ALPHA",				0x0184)
							   ("IMAGE_FILE_MACHINE_SH3",				0x01a2)
							   ("IMAGE_FILE_MACHINE_SH3DSP",			0x01a3)
							   ("IMAGE_FILE_MACHINE_SH3E",				0x01a4)
							   ("IMAGE_FILE_MACHINE_SH4",				0x01a6)
							   ("IMAGE_FILE_MACHINE_SH5",				0x01a8)
							   ("IMAGE_FILE_MACHINE_ARM",				0x01c0)
							   ("IMAGE_FILE_MACHINE_THUMB",				0x01c2)
							   ("IMAGE_FILE_MACHINE_AM33",				0x01d3)
							   ("IMAGE_FILE_MACHINE_POWERPC",			0x01F0)
							   ("IMAGE_FILE_MACHINE_POWERPCFP",			0x01f1)
							   ("IMAGE_FILE_MACHINE_IA64",				0x0200)
							   ("IMAGE_FILE_MACHINE_MIPS16",			0x0266)
							   ("IMAGE_FILE_MACHINE_ALPHA64",			0x0284)
							   ("IMAGE_FILE_MACHINE_MIPSFPU",			0x0366)
							   ("IMAGE_FILE_MACHINE_MIPSFPU16",			0x0466)
							   ("IMAGE_FILE_MACHINE_TRICORE",			0x0520)
							   ("IMAGE_FILE_MACHINE_CEF",				0x0CEF)
							   ("IMAGE_FILE_MACHINE_EBC",				0x0EBC)
							   ("IMAGE_FILE_MACHINE_AMD64",				0x8664)
							   ("IMAGE_FILE_MACHINE_M32R",				0x9041)
							   ("IMAGE_FILE_MACHINE_CEE",				0xC0EE);

static flag_dict IMAGE_OPTIONAL_HEADER_MAGIC =
	boost::assign::map_list_of ("PE32",		0x10b)
							   ("PE32+",	0x20b);

static flag_dict SUBSYSTEMS =
	boost::assign::map_list_of ("IMAGE_SUBSYSTEM_UNKNOWN", 0)
							   ("IMAGE_SUBSYSTEM_NATIVE", 1)
							   ("IMAGE_SUBSYSTEM_WINDOWS_GUI", 2)
							   ("IMAGE_SUBSYSTEM_WINDOWS_CUI", 3)
							   ("IMAGE_SUBSYSTEM_POSIX_CUI", 7)
							   ("IMAGE_SUBSYSTEM_NATIVE_WINDOWS", 8)
							   ("IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", 9)
							   ("IMAGE_SUBSYSTEM_EFI_APPLICATION", 10)
							   ("IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", 11)
							   ("IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", 12)
							   ("IMAGE_SUBSYSTEM_EFI_ROM", 13)
							   ("IMAGE_SUBSYSTEM_XBOX", 14)
							   ("IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", 16);

static flag_dict DLL_CHARACTERISTICS =
	boost::assign::map_list_of ("IMAGE_LIBRARY_PROCESS_INIT",						0x0001)
							   ("IMAGE_LIBRARY_PROCESS_TERM",						0x0002)
							   ("IMAGE_LIBRARY_THREAD_INIT",						0x0004)
							   ("IMAGE_LIBRARY_THREAD_TERM",						0x0008)
							   ("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",			0x0020)
							   ("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",			0x0040)
							   ("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",			0x0080)
							   ("IMAGE_DLLCHARACTERISTICS_NX_COMPAT",				0x0100)
							   ("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",			0x0200)
							   ("IMAGE_DLLCHARACTERISTICS_NO_SEH",					0x0400)
							   ("IMAGE_DLLCHARACTERISTICS_NO_BIND",					0x0800)
							   ("IMAGE_DLLCHARACTERISTICS_APPCONTAINER",			0x1000)
							   ("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",				0x2000)
							   ("IMAGE_DLLCHARACTERISTICS_GUARD_CF",				0x4000)
							   ("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE",	0x8000);

static flag_dict SECTION_CHARACTERISTICS =
	boost::assign::map_list_of ("IMAGE_SCN_TYPE_REG",				0x00000000)
							   ("IMAGE_SCN_TYPE_DSECT",				0x00000001)
							   ("IMAGE_SCN_TYPE_NOLOAD",			0x00000002)
							   ("IMAGE_SCN_TYPE_GROUP",				0x00000004)
							   ("IMAGE_SCN_TYPE_NO_PAD",			0x00000008)
							   ("IMAGE_SCN_TYPE_COPY",				0x00000010)
							   ("IMAGE_SCN_CNT_CODE",				0x00000020)
							   ("IMAGE_SCN_CNT_INITIALIZED_DATA",	0x00000040)
							   ("IMAGE_SCN_CNT_UNINITIALIZED_DATA", 0x00000080)
							   ("IMAGE_SCN_LNK_OTHER",				0x00000100)
							   ("IMAGE_SCN_LNK_INFO",				0x00000200)
							   ("IMAGE_SCN_TYPE_OVER",				0x00000400)
							   ("IMAGE_SCN_LNK_REMOVE",				0x00000800)
							   ("IMAGE_SCN_LNK_COMDAT",				0x00001000)
							   ("IMAGE_SCN_NO_DEFER_SPEC_EXC",		0x00004000)
							   ("IMAGE_SCN_GPREL",					0x00008000)
							   ("IMAGE_SCN_MEM_FARDATA",			0x00008000)
							   ("IMAGE_SCN_MEM_PURGEABLE",			0x00020000)
							   ("IMAGE_SCN_MEM_LOCKED",				0x00040000)
							   ("IMAGE_SCN_MEM_PRELOAD",			0x00080000)
							   ("IMAGE_SCN_ALIGN_MASK",				0x00F00000)
							   ("IMAGE_SCN_LNK_NRELOC_OVFL",		0x01000000)
							   ("IMAGE_SCN_MEM_DISCARDABLE",		0x02000000)
							   ("IMAGE_SCN_MEM_NOT_CACHED",			0x04000000)
							   ("IMAGE_SCN_MEM_NOT_PAGED",			0x08000000)
							   ("IMAGE_SCN_MEM_SHARED",				0x10000000)
							   ("IMAGE_SCN_MEM_EXECUTE",			0x20000000)
							   ("IMAGE_SCN_MEM_READ",				0x40000000)
							   ("IMAGE_SCN_MEM_WRITE",				0x80000000);

static flag_dict RESOURCE_TYPES =
	boost::assign::map_list_of ("RT_CURSOR",		1)
							   ("RT_BITMAP",		2)
							   ("RT_ICON",			3)
							   ("RT_MENU",			4)
							   ("RT_DIALOG",		5)
							   ("RT_STRING",		6)
							   ("RT_FONTDIR",		7)
							   ("RT_FONT",			8)
							   ("RT_ACCELERATOR",	9)
							   ("RT_RCDATA",		10)
							   ("RT_MESSAGETABLE",	11)
							   ("RT_GROUP_CURSOR",	12)
							   ("RT_GROUP_ICON",	14)
							   ("RT_VERSION",		16)
							   ("RT_DLGINCLUDE",	17)
							   ("RT_PLUGPLAY",		19)
							   ("RT_VXD",			20)
							   ("RT_ANICURSOR",		21)
							   ("RT_ANIICON",		22)
							   ("RT_HTML",			23)
							   ("RT_MANIFEST",		24);

// Source: http://msdn.microsoft.com/en-us/library/windows/desktop/aa381058%28v=vs.85%29.aspx
static flag_dict LANG_IDS =
	boost::assign::map_list_of ("Arabic",						0x0401)
							   ("Polish",						0x0415)
							   ("Bulgarian",					0x0402)
							   ("Portuguese (Brazil)",			0x0416)
							   ("Catalan",						0x0403)
							   ("Rhaeto-Romanic",				0x0417)
							   ("Traditional Chinese",			0x0404)
							   ("Romanian",						0x0418)
							   ("Czech",						0x0405)
							   ("Russian",						0x0419)
							   ("Danish",						0x0406)
							   ("Croato-Serbian (Latin)",		0x041A)
							   ("German",						0x0407)
							   ("Slovak",						0x041B)
							   ("Greek",						0x0408)
							   ("Albanian",						0x041C)
							   ("U.S. English",					0x0409)
							   ("Swedish",						0x041D)
							   ("Castilian Spanish",			0x040A)
							   ("Thai",							0x041E)
							   ("Finnish",						0x040B)
							   ("Turkish",						0x041F)
							   ("French",						0x040C)
							   ("Urdu",							0x0420)
							   ("Hebrew",						0x040D)
							   ("Bahasa",						0x0421)
							   ("Hungarian",					0x040E)
							   ("Simplified Chinese",			0x0804)
							   ("Icelandic",					0x040F)
							   ("Swiss German",					0x0807)
							   ("Italian",						0x0410)
							   ("U.K. English",					0x0809)
							   ("Japanese",						0x0411)
							   ("Spanish (Mexico)",				0x080A)
							   ("Korean",						0x0412)
							   ("Belgian French",				0x080C)
							   ("Dutch",						0x0413)
							   ("Canadian French",				0x0C0C)
							   ("Norwegian ? Bokmal",			0x0414)
							   ("Swiss French",					0x100C)
							   ("Swiss Italian",				0x0810)
							   ("Portuguese (Portugal)",		0x0816)
							   ("Belgian Dutch",				0x0813)
							   ("Serbo-Croatian (Cyrillic)",	0x081A)
							   ("Norwegian ? Nynorsk",			0x0814);

static flag_dict FIXEDFILEINFO_FILEFLAGS =
	boost::assign::map_list_of ("VS_FF_DEBUG",					0x00000001)
							   ("VS_FF_PRERELEASE",				0x00000002)
							   ("VS_FF_PATCHED",				0x00000004)
							   ("VS_FF_PRIVATEBUILD",			0x00000008)
							   ("VS_FF_INFOINFERRED",			0x00000010)
							   ("VS_FF_SPECIALBUILD",			0x00000020);

static flag_dict FIXEDFILEINFO_FILEOS =
	boost::assign::map_list_of ("VOS_UNKNOWN",					0x00000000)
							   ("VOS_DOS",						0x00010000)
							   ("VOS_OS216",					0x00020000)
							   ("VOS_OS232",					0x00030000)
							   ("VOS_NT",						0x00040000)
							   ("VOS_WINCE",					0x00050000)
							   ("VOS__WINDOWS16",				0x00000001)
							   ("VOS__PM16",					0x00000002)
							   ("VOS__PM32",					0x00000003)
							   ("VOS__WINDOWS32",				0x00000004)
							   ("VOS_DOS_WINDOWS16",			0x00010001)
							   ("VOS_DOS_WINDOWS32",			0x00010004)
							   ("VOS_OS216_PM16",				0x00020002)
							   ("VOS_OS232_PM32",				0x00030003)
							   ("VOS_NT_WINDOWS32",				0x00040004);

static flag_dict FIXEDFILEINFO_FILETYPE =
	boost::assign::map_list_of ("VFT_UNKNOWN",					0x00000000)
							   ("VFT_APP",						0x00000001)
							   ("VFT_DLL",						0x00000002)
							   ("VFT_DRV",						0x00000003)
							   ("VFT_FONT",						0x00000004)
							   ("VFT_VXD",						0x00000005)
							   ("VFT_STATIC_LIB",				0x00000007);

static flag_dict FIXEDFILEINFO_FILESUBTYPE_DRV =
	boost::assign::map_list_of ("VFT2_UNKNOWN",					0x00000000)
							   ("VFT2_DRV_PRINTER",				0x00000001)
							   ("VFT2_DRV_KEYBOARD",			0x00000002)
							   ("VFT2_DRV_LANGUAGE",			0x00000003)
							   ("VFT2_DRV_DISPLAY",				0x00000004)
							   ("VFT2_DRV_MOUSE",				0x00000005)
							   ("VFT2_DRV_NETWORK",				0x00000006)
							   ("VFT2_DRV_SYSTEM",				0x00000007)
							   ("VFT2_DRV_INSTALLABLE",			0x00000008)
							   ("VFT2_DRV_SOUND",				0x00000009)
							   ("VFT2_DRV_COMM",				0x0000000A)
							   ("VFT2_DRV_INPUTMETHOD",			0x0000000B)
							   ("VFT2_DRV_VERSIONED_PRINTER",	0x0000000C);

static flag_dict FIXEDFILEINFO_FILESUBTYPE_FONT =
	boost::assign::map_list_of ("VFT2_FONT_RASTER",				0x00000001)
							   ("VFT2_FONT_VECTOR",				0x00000002)
							   ("VFT2_FONT_TRUETYPE",			0x00000003);

static flag_dict DEBUG_TYPES =
	boost::assign::map_list_of ("IMAGE_DEBUG_TYPE_UNKNOWN",			0)
							   ("IMAGE_DEBUG_TYPE_COFF",			1)
							   ("IMAGE_DEBUG_TYPE_CODEVIEW",		2)
							   ("IMAGE_DEBUG_TYPE_FPO",				3)
							   ("IMAGE_DEBUG_TYPE_MISC",			4)
							   ("IMAGE_DEBUG_TYPE_EXCEPTION",		5)
							   ("IMAGE_DEBUG_TYPE_FIXUP",			6)
							   ("IMAGE_DEBUG_TYPE_OMAP_TO_SRC",		7)
							   ("IMAGE_DEBUG_TYPE_OMAP_FROM_SRC",	8)
							   ("IMAGE_DEBUG_TYPE_BORLAND",			9)
							   ("IMAGE_DEBUG_TYPE_RESERVED",		10)
							   ("IMAGE_DEBUG_TYPE_CLSID",			11);

static flag_dict BASE_RELOCATION_TYPES =
	boost::assign::map_list_of ("IMAGE_REL_BASED_ABSOLUTE",			0)
							   ("IMAGE_REL_BASED_HIGH",				1)
							   ("IMAGE_REL_BASED_LOW",				2)
							   ("IMAGE_REL_BASED_HIGHLOW",			3)
							   ("IMAGE_REL_BASED_HIGHADJ",			4)
							   ("IMAGE_REL_BASED_MIPS_JMPADDR16",	9)
							   ("IMAGE_REL_BASED_IA64_IMM64",		9)
							   ("IMAGE_REL_BASED_DIR64",			10);



/**
 *	@brief	Breaks down an integer given as input as a combination of flags.
 *
 *	@param	int value The integer to translate
 *	@param	flag_dict& dict A map containing the list of available flags and corresponding
 *			integer values.
 *
 *	@return	A list of matching flags.
 */
std::vector<std::string> translate_to_flags(int value, const flag_dict& dict);

/**
 *	@brief	Looks up the flag corresponding to a given value, if any.
 *
 *	@param	int value The integer to translate
 *	@param	flag_dict& dict A map containing the list of available flags and corresponding
 *			integer values.
 *
 *	@return	The corresponding flag, or "UNKNOWN" if no match is found.
 */
std::string translate_to_flag(int value, const flag_dict& dict);

} // !namespace nt

#endif