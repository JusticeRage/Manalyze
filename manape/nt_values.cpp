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

#include "manape/nt_values.h"


namespace nt {


const flag_dict DLL_CHARACTERISTICS =
    boost::assign::map_list_of ("IMAGE_LIBRARY_PROCESS_INIT",                      0x0001)
                               ("IMAGE_LIBRARY_PROCESS_TERM",                      0x0002)
                               ("IMAGE_LIBRARY_THREAD_INIT",                       0x0004)
                               ("IMAGE_LIBRARY_THREAD_TERM",                       0x0008)
                               ("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",        0x0020)
                               ("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",           0x0040)
                               ("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",        0x0080)
                               ("IMAGE_DLLCHARACTERISTICS_NX_COMPAT",              0x0100)
                               ("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",           0x0200)
                               ("IMAGE_DLLCHARACTERISTICS_NO_SEH",                 0x0400)
                               ("IMAGE_DLLCHARACTERISTICS_NO_BIND",                0x0800)
                               ("IMAGE_DLLCHARACTERISTICS_APPCONTAINER",           0x1000)
                               ("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",             0x2000)
                               ("IMAGE_DLLCHARACTERISTICS_GUARD_CF",               0x4000)
                               ("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE",  0x8000);

// ----------------------------------------------------------------------------

const flag_dict SECTION_CHARACTERISTICS =
    boost::assign::map_list_of ("IMAGE_SCN_TYPE_REG",               0x00000000)
                               ("IMAGE_SCN_TYPE_DSECT",             0x00000001)
                               ("IMAGE_SCN_TYPE_NOLOAD",            0x00000002)
                               ("IMAGE_SCN_TYPE_GROUP",             0x00000004)
                               ("IMAGE_SCN_TYPE_NO_PAD",            0x00000008)
                               ("IMAGE_SCN_TYPE_COPY",              0x00000010)
                               ("IMAGE_SCN_CNT_CODE",               0x00000020)
                               ("IMAGE_SCN_CNT_INITIALIZED_DATA",   0x00000040)
                               ("IMAGE_SCN_CNT_UNINITIALIZED_DATA", 0x00000080)
                               ("IMAGE_SCN_LNK_OTHER",              0x00000100)
                               ("IMAGE_SCN_LNK_INFO",               0x00000200)
                               ("IMAGE_SCN_TYPE_OVER",              0x00000400)
                               ("IMAGE_SCN_LNK_REMOVE",             0x00000800)
                               ("IMAGE_SCN_LNK_COMDAT",             0x00001000)
                               ("IMAGE_SCN_NO_DEFER_SPEC_EXC",      0x00004000)
                               ("IMAGE_SCN_GPREL",                  0x00008000) // Some sources report this to flag be IMAGE_SCN_MEM_FARDATA.
                               ("IMAGE_SCN_MEM_PURGEABLE",          0x00020000)
                               ("IMAGE_SCN_MEM_LOCKED",             0x00040000)
                               ("IMAGE_SCN_MEM_PRELOAD",            0x00080000)
                               ("IMAGE_SCN_ALIGN_1BYTES",           0x00100000)
                               ("IMAGE_SCN_ALIGN_2BYTES",           0x00200000)
                               ("IMAGE_SCN_ALIGN_4BYTES",           0x00300000)
                               ("IMAGE_SCN_ALIGN_8BYTES",           0x00400000)
                               ("IMAGE_SCN_ALIGN_16BYTES",          0x00500000)
                               ("IMAGE_SCN_ALIGN_32BYTES",          0x00600000)
                               ("IMAGE_SCN_ALIGN_64BYTES",          0x00700000)
                               ("IMAGE_SCN_ALIGN_128BYTES",         0x00800000)
                               ("IMAGE_SCN_ALIGN_256BYTES",         0x00900000)
                               ("IMAGE_SCN_ALIGN_512BYTES",         0x00A00000)
                               ("IMAGE_SCN_ALIGN_1024BYTES",        0x00B00000)
                               ("IMAGE_SCN_ALIGN_2048BYTES",        0x00C00000)
                               ("IMAGE_SCN_ALIGN_4096BYTES",        0x00D00000)
                               ("IMAGE_SCN_ALIGN_8192BYTES",        0x00E00000)
                               ("IMAGE_SCN_ALIGN_MASK",             0x00F00000)
                               ("IMAGE_SCN_LNK_NRELOC_OVFL",        0x01000000)
                               ("IMAGE_SCN_MEM_DISCARDABLE",        0x02000000)
                               ("IMAGE_SCN_MEM_NOT_CACHED",         0x04000000)
                               ("IMAGE_SCN_MEM_NOT_PAGED",          0x08000000)
                               ("IMAGE_SCN_MEM_SHARED",             0x10000000)
                               ("IMAGE_SCN_MEM_EXECUTE",            0x20000000)
                               ("IMAGE_SCN_MEM_READ",               0x40000000)
                               ("IMAGE_SCN_MEM_WRITE",              0x80000000);

// ----------------------------------------------------------------------------

const flag_dict PE_CHARACTERISTICS =
    boost::assign::map_list_of ("IMAGE_FILE_RELOCS_STRIPPED",         0x0001)
                               ("IMAGE_FILE_EXECUTABLE_IMAGE",        0x0002)
                               ("IMAGE_FILE_LINE_NUMS_STRIPPED",      0x0004)
                               ("IMAGE_FILE_LOCAL_SYMS_STRIPPED",     0x0008)
                               ("IMAGE_FILE_AGGRESIVE_WS_TRIM",       0x0010)
                               ("IMAGE_FILE_LARGE_ADDRESS_AWARE",     0x0020)
                               ("IMAGE_FILE_BYTES_REVERSED_LO",       0x0080)
                               ("IMAGE_FILE_32BIT_MACHINE",           0x0100)
                               ("IMAGE_FILE_DEBUG_STRIPPED",          0x0200)
                               ("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 0x0400)
                               ("IMAGE_FILE_NET_RUN_FROM_SWAP",       0x0800)
                               ("IMAGE_FILE_SYSTEM",                  0x1000)
                               ("IMAGE_FILE_DLL",                     0x2000)
                               ("IMAGE_FILE_UP_SYSTEM_ONLY",          0x4000)
                               ("IMAGE_FILE_BYTES_REVERSED_HI",       0x8000);

// ----------------------------------------------------------------------------

const flag_dict MACHINE_TYPES =
    boost::assign::map_list_of ("IMAGE_FILE_MACHINE_UNKNOWN",           0)
                               ("IMAGE_FILE_MACHINE_I386",              0x014c)
                               ("IMAGE_FILE_MACHINE_R3000",             0x0162)
                               ("IMAGE_FILE_MACHINE_R4000",             0x0166)
                               ("IMAGE_FILE_MACHINE_R10000",            0x0168)
                               ("IMAGE_FILE_MACHINE_WCEMIPSV2",         0x0169)
                               ("IMAGE_FILE_MACHINE_ALPHA",             0x0184)
                               ("IMAGE_FILE_MACHINE_SH3",               0x01a2)
                               ("IMAGE_FILE_MACHINE_SH3DSP",            0x01a3)
                               ("IMAGE_FILE_MACHINE_SH3E",              0x01a4)
                               ("IMAGE_FILE_MACHINE_SH4",               0x01a6)
                               ("IMAGE_FILE_MACHINE_SH5",               0x01a8)
                               ("IMAGE_FILE_MACHINE_ARM",               0x01c0)
                               ("IMAGE_FILE_MACHINE_THUMB",             0x01c2)
                               ("IMAGE_FILE_MACHINE_AM33",              0x01d3)
                               ("IMAGE_FILE_MACHINE_POWERPC",           0x01F0)
                               ("IMAGE_FILE_MACHINE_POWERPCFP",         0x01f1)
                               ("IMAGE_FILE_MACHINE_IA64",              0x0200)
                               ("IMAGE_FILE_MACHINE_MIPS16",            0x0266)
                               ("IMAGE_FILE_MACHINE_ALPHA64",           0x0284)
                               ("IMAGE_FILE_MACHINE_MIPSFPU",           0x0366)
                               ("IMAGE_FILE_MACHINE_MIPSFPU16",         0x0466)
                               ("IMAGE_FILE_MACHINE_TRICORE",           0x0520)
                               ("IMAGE_FILE_MACHINE_CEF",               0x0CEF)
                               ("IMAGE_FILE_MACHINE_EBC",               0x0EBC)
                               ("IMAGE_FILE_MACHINE_AMD64",             0x8664)
                               ("IMAGE_FILE_MACHINE_M32R",              0x9041)
                               ("IMAGE_FILE_MACHINE_CEE",               0xC0EE);

// ----------------------------------------------------------------------------

const flag_dict SUBSYSTEMS =
    boost::assign::map_list_of ("IMAGE_SUBSYSTEM_UNKNOWN",                  0)
                               ("IMAGE_SUBSYSTEM_NATIVE",                   1)
                               ("IMAGE_SUBSYSTEM_WINDOWS_GUI",              2)
                               ("IMAGE_SUBSYSTEM_WINDOWS_CUI",              3)
                               ("IMAGE_SUBSYSTEM_POSIX_CUI",                7)
                               ("IMAGE_SUBSYSTEM_NATIVE_WINDOWS",           8)
                               ("IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",           9)
                               ("IMAGE_SUBSYSTEM_EFI_APPLICATION",          10)
                               ("IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",  11)
                               ("IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",       12)
                               ("IMAGE_SUBSYSTEM_EFI_ROM",                  13)
                               ("IMAGE_SUBSYSTEM_XBOX",                     14)
                               ("IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", 16);

// ----------------------------------------------------------------------------

const flag_dict IMAGE_OPTIONAL_HEADER_MAGIC =
    boost::assign::map_list_of ("PE32",  0x10b)
                               ("PE32+", 0x20b);

// ----------------------------------------------------------------------------

const flag_dict RESOURCE_TYPES =
    boost::assign::map_list_of ("RT_CURSOR",       1)
                               ("RT_BITMAP",       2)
                               ("RT_ICON",         3)
                               ("RT_MENU",         4)
                               ("RT_DIALOG",       5)
                               ("RT_STRING",       6)
                               ("RT_FONTDIR",      7)
                               ("RT_FONT",         8)
                               ("RT_ACCELERATOR",  9)
                               ("RT_RCDATA",       10)
                               ("RT_MESSAGETABLE", 11)
                               ("RT_GROUP_CURSOR", 12)
                               ("RT_GROUP_ICON",   14)
                               ("RT_VERSION",      16)
                               ("RT_DLGINCLUDE",   17)
                               ("RT_PLUGPLAY",     19)
                               ("RT_VXD",          20)
                               ("RT_ANICURSOR",    21)
                               ("RT_ANIICON",      22)
                               ("RT_HTML",         23)
                               ("RT_MANIFEST",     24);

// ----------------------------------------------------------------------------

// Source: https://msdn.microsoft.com/en-us/library/aa912040.aspx
extern const DECLSPEC flag_dict LANG_IDS =
    boost::assign::map_list_of  ("Afrikaans - South Africa",                0x0436)
                                ("Albanian - Albania",                      0x041c)
                                ("Arabic - Algeria",                        0x1401)
                                ("Arabic - Bahrain",                        0x3c01)
                                ("Arabic - Egypt",                          0x0c01)
                                ("Arabic - Iraq",                           0x0801)
                                ("Arabic - Jordan",                         0x2c01)
                                ("Arabic - Kuwait",                         0x3401)
                                ("Arabic - Lebanon",                        0x3001)
                                ("Arabic - Libya",                          0x1001)
                                ("Arabic - Morocco",                        0x1801)
                                ("Arabic - Oman",                           0x2001)
                                ("Arabic - Qatar",                          0x4001)
                                ("Arabic - Saudi Arabia",                   0x0401)
                                ("Arabic - Syria",                          0x2801)
                                ("Arabic - Tunisia",                        0x1c01)
                                ("Arabic - U.A.E.",                         0x3801)
                                ("Arabic - Yemen",                          0x2401)
                                ("Armenian - Armenia",                      0x042b)
                                ("Azeri - Azerbaijan (Cyrillic)",           0x082c)
                                ("Azeri - Azerbaijan (Latin)",              0x042c)
                                ("Basque - Spain",                          0x042d)
                                ("Belarusian - Belarus",                    0x0423)
                                ("Bulgarian - Bulgaria",                    0x0402)
                                ("Catalan - Spain",                         0x0403)
                                ("Chinese - Hong Kong SAR",                 0x0c04)
                                ("Chinese - Macao SAR",                     0x1404)
                                ("Chinese - PRC",                           0x0804)
                                ("Chinese - Singapore",                     0x1004)
                                ("Chinese - Taiwan",                        0x0404)
                                ("Croatian - Croatia",                      0x041a)
                                ("Czech - Czech Republic",                  0x0405)
                                ("Danish - Denmark",                        0x0406)
                                ("Divehi - Maldives",                       0x0465)
                                ("Dutch - Belgium",                         0x0813)
                                ("Dutch - Netherlands",                     0x0413)
                                ("English - Australia",                     0x0c09)
                                ("English - Belize",                        0x2809)
                                ("English - Canada",                        0x1009)
                                ("English - Caribbean",                     0x2409)
                                ("English - Ireland",                       0x1809)
                                ("English - Jamaica",                       0x2009)
                                ("English - New Zealand",                   0x1409)
                                ("English - Philippines",                   0x3409)
                                ("English - South Africa",                  0x1c09)
                                ("English - Trinidad",                      0x2c09)
                                ("English - United Kingdom",                0x0809)
                                ("English - United States",                 0x0409)
                                ("English - Zimbabwe",                      0x3009)
                                ("Estonian - Estonia",                      0x0425)
                                ("Faroese - Faroe Islands",                 0x0438)
                                ("Farsi - Iran",                            0x0429)
                                ("Finnish - Finland",                       0x040b)
                                ("French - Belgium",                        0x080c)
                                ("French - Canada",                         0x0c0c)
                                ("French - France",                         0x040c)
                                ("French - Luxembourg",                     0x140c)
                                ("French - Monaco",                         0x180c)
                                ("French - Switzerland",                    0x100c)
                                ("F.Y.R.O. Macedonia - F.Y.R.O. Macedonia", 0x042f)
                                ("Galician - Spain",                        0x0456)
                                ("Georgian - Georgia",                      0x0437)
                                ("German - Austria",                        0x0c07)
                                ("German - Germany",                        0x0407)
                                ("German - Liechtenstein",                  0x1407)
                                ("German - Luxembourg",                     0x1007)
                                ("German - Switzerland",                    0x0807)
                                ("Greek - Greece",                          0x0408)
                                ("Gujarati - India",                        0x0447)
                                ("Hebrew - Israel",                         0x040d)
                                ("Hindi - India",                           0x0439)
                                ("Hungarian - Hungary",                     0x040e)
                                ("Icelandic - Iceland",                     0x040f)
                                ("Indonesian - Indonesia (Bahasa)",         0x0421)
                                ("Italian - Italy",                         0x0410)
                                ("Italian - Switzerland",                   0x0810)
                                ("Japanese - Japan",                        0x0411)
                                ("Kannada - India (Kannada script)",        0x044b)
                                ("Kazakh - Kazakstan",                      0x043f)
                                ("Konkani - India",                         0x0457)
                                ("Korean - Korea",                          0x0412)
                                ("Kyrgyz - Kyrgyzstan",                     0x0440)
                                ("Latvian - Latvia",                        0x0426)
                                ("Lithuanian - Lithuania",                  0x0427)
                                ("Malay - Brunei Darussalam",               0x083e)
                                ("Malay - Malaysia",                        0x043e)
                                ("Marathi - India",                         0x044e)
                                ("Mongolian (Cyrillic) - Mongolia",         0x0450)
                                ("Norwegian - Norway (Bokmal)",             0x0414)
                                ("Norwegian - Norway (Nynorsk)",            0x0814)
                                ("Polish - Poland",                         0x0415)
                                ("Portuguese - Brazil",                     0x0416)
                                ("Portuguese - Portugal",                   0x0816)
                                ("Punjabi - India (Gurmukhi script)",       0x0446)
                                ("Romanian - Romania",                      0x0418)
                                ("Russian - Russia",                        0x0419)
                                ("Sanskrit - India",                        0x044f)
                                ("Serbian - Serbia (Cyrillic)",             0x0c1a)
                                ("Serbian - Serbia (Latin)",                0x081a)
                                ("Slovak - Slovakia",                       0x041b)
                                ("Slovenian - Slovenia",                    0x0424)
                                ("Spanish - Argentina",                     0x2c0a)
                                ("Spanish - Bolivia",                       0x400a)
                                ("Spanish - Chile",                         0x340a)
                                ("Spanish - Colombia",                      0x240a)
                                ("Spanish - Costa Rica",                    0x140a)
                                ("Spanish - Dominican Republic",            0x1c0a)
                                ("Spanish - Ecuador",                       0x300a)
                                ("Spanish - El Salvador",                   0x440a)
                                ("Spanish - Guatemala",                     0x100a)
                                ("Spanish - Honduras",                      0x480a)
                                ("Spanish - Mexico",                        0x080a)
                                ("Spanish - Nicaragua",                     0x4c0a)
                                ("Spanish - Panama",                        0x180a)
                                ("Spanish - Paraguay",                      0x3c0a)
                                ("Spanish - Peru",                          0x280a)
                                ("Spanish - Puerto Rico",                   0x500a)
                                ("Spanish - Spain (Traditional sort)",      0x040a)
                                ("Spanish - Spain (International sort)",    0x0c0a)
                                ("Spanish - Uruguay",                       0x380a)
                                ("Spanish - Venezuela",                     0x200a)
                                ("Swahili - Kenya",                         0x0441)
                                ("Swedish - Finland",                       0x081d)
                                ("Swedish - Sweden",                        0x041d)
                                ("Syriac - Syria",                          0x045a)
                                ("Tamil - India",                           0x0449)
                                ("Tatar - Tatarstan",                       0x0444)
                                ("Telugu - India (Telugu script)",          0x044a)
                                ("Thai - Thailand",                         0x041e)
                                ("Turkish - Turkey",                        0x041f)
                                ("Ukrainian - Ukraine",                     0x0422)
                                ("Urdu - Pakistan",                         0x0420)
                                ("Uzbek - Uzbekistan (Cyrillic)",           0x0843)
                                ("Uzbek - Uzbekistan (Latin)",              0x0443)
                                ("Vietnamese - Viet Nam",                   0x042a)
                                ("Process Default Language",                0x0400);

// ----------------------------------------------------------------------------

const flag_dict CODEPAGES =
        boost::assign::map_list_of ("IBM EBCDIC US-Canada",       37)
                                   ("IBM PC US",                  437)
                                   ("Thai",                       874)
                                   ("Japanese",                   932)
                                   ("Chinese (simplified)",       936)
                                   ("Korean",                     949)
                                   ("Chinese (traditional)",      950)
                                   ("Unicode (UTF 16LE)",         1200)
                                   ("Unicode (UTF 16BE)",         1201)
                                   ("Latin 2 / Central European", 1250)
                                   ("Cyrillic",                   1251)
                                   ("Latin 1 / Western European", 1252)
                                   ("Greek",                      1253)
                                   ("Turkish",                    1254)
                                   ("Hebrew",                     1255)
                                   ("Arabic",                     1256)
                                   ("Baltic",                     1257)
                                   ("Vietnamese",                 1258)
                                   ("US-ASCII",                   20127)
                                   ("Russian (KOI8-R)",           20866)
                                   ("ISO 8859-1",                 28591)
                                   ("ISO 8859-2",                 28592)
                                   ("ISO 8859-3",                 28593)
                                   ("Unicode (UTF-7)",            65000)
                                   ("Unicode (UTF-8)",            65001);

// ----------------------------------------------------------------------------

const flag_dict FIXEDFILEINFO_FILEFLAGS =
    boost::assign::map_list_of ("VS_FF_DEBUG",                    0x00000001)
                               ("VS_FF_PRERELEASE",               0x00000002)
                               ("VS_FF_PATCHED",                  0x00000004)
                               ("VS_FF_PRIVATEBUILD",             0x00000008)
                               ("VS_FF_INFOINFERRED",             0x00000010)
                               ("VS_FF_SPECIALBUILD",             0x00000020);

// ----------------------------------------------------------------------------

const flag_dict FIXEDFILEINFO_FILEOS =
    boost::assign::map_list_of ("VOS_UNKNOWN",                    0x00000000)
                               ("VOS_DOS",                        0x00010000)
                               ("VOS_OS216",                      0x00020000)
                               ("VOS_OS232",                      0x00030000)
                               ("VOS_NT",                         0x00040000)
                               ("VOS_WINCE",                      0x00050000)
                               ("VOS__WINDOWS16",                 0x00000001)
                               ("VOS__PM16",                      0x00000002)
                               ("VOS__PM32",                      0x00000003)
                               ("VOS__WINDOWS32",                 0x00000004)
                               ("VOS_DOS_WINDOWS16",              0x00010001)
                               ("VOS_DOS_WINDOWS32",              0x00010004)
                               ("VOS_OS216_PM16",                 0x00020002)
                               ("VOS_OS232_PM32",                 0x00030003)
                               ("VOS_NT_WINDOWS32",               0x00040004);

// ----------------------------------------------------------------------------

const flag_dict FIXEDFILEINFO_FILETYPE =
    boost::assign::map_list_of ("VFT_UNKNOWN",                    0x00000000)
                               ("VFT_APP",                        0x00000001)
                               ("VFT_DLL",                        0x00000002)
                               ("VFT_DRV",                        0x00000003)
                               ("VFT_FONT",                       0x00000004)
                               ("VFT_VXD",                        0x00000005)
                               ("VFT_STATIC_LIB",                 0x00000007);

// ----------------------------------------------------------------------------

const flag_dict FIXEDFILEINFO_FILESUBTYPE_DRV =
    boost::assign::map_list_of ("VFT2_UNKNOWN",                   0x00000000)
                               ("VFT2_DRV_PRINTER",               0x00000001)
                               ("VFT2_DRV_KEYBOARD",              0x00000002)
                               ("VFT2_DRV_LANGUAGE",              0x00000003)
                               ("VFT2_DRV_DISPLAY",               0x00000004)
                               ("VFT2_DRV_MOUSE",                 0x00000005)
                               ("VFT2_DRV_NETWORK",               0x00000006)
                               ("VFT2_DRV_SYSTEM",                0x00000007)
                               ("VFT2_DRV_INSTALLABLE",           0x00000008)
                               ("VFT2_DRV_SOUND",                 0x00000009)
                               ("VFT2_DRV_COMM",                  0x0000000A)
                               ("VFT2_DRV_INPUTMETHOD",           0x0000000B)
                               ("VFT2_DRV_VERSIONED_PRINTER",     0x0000000C);

// ----------------------------------------------------------------------------

const flag_dict FIXEDFILEINFO_FILESUBTYPE_FONT =
    boost::assign::map_list_of ("VFT2_FONT_RASTER",               0x00000001)
                               ("VFT2_FONT_VECTOR",               0x00000002)
                               ("VFT2_FONT_TRUETYPE",             0x00000003);

// ----------------------------------------------------------------------------

const flag_dict DEBUG_TYPES =
    boost::assign::map_list_of ("IMAGE_DEBUG_TYPE_UNKNOWN",       0)
                               ("IMAGE_DEBUG_TYPE_COFF",          1)
                               ("IMAGE_DEBUG_TYPE_CODEVIEW",      2)
                               ("IMAGE_DEBUG_TYPE_FPO",           3)
                               ("IMAGE_DEBUG_TYPE_MISC",          4)
                               ("IMAGE_DEBUG_TYPE_EXCEPTION",     5)
                               ("IMAGE_DEBUG_TYPE_FIXUP",         6)
                               ("IMAGE_DEBUG_TYPE_OMAP_TO_SRC",   7)
                               ("IMAGE_DEBUG_TYPE_OMAP_FROM_SRC", 8)
                               ("IMAGE_DEBUG_TYPE_BORLAND",       9)
                               ("IMAGE_DEBUG_TYPE_RESERVED",      10)
                               ("IMAGE_DEBUG_TYPE_CLSID",         11)
                               ("IMAGE_DEBUG_TYPE_VC_FEATURE",    12)
                               ("IMAGE_DEBUG_TYPE_POGO",          13)
                               ("IMAGE_DEBUG_TYPE_ILTCG",         14)
                               ("IMAGE_DEBUG_TYPE_MPX",           15);

// ----------------------------------------------------------------------------

const flag_dict BASE_RELOCATION_TYPES =
    boost::assign::map_list_of ("IMAGE_REL_BASED_ABSOLUTE",       0)
                               ("IMAGE_REL_BASED_HIGH",           1)
                               ("IMAGE_REL_BASED_LOW",            2)
                               ("IMAGE_REL_BASED_HIGHLOW",        3)
                               ("IMAGE_REL_BASED_HIGHADJ",        4)
                               ("IMAGE_REL_BASED_MIPS_JMPADDR",   5)
                               ("RESERVED",                       6)
                               ("IMAGE_REL_BASED_THUMB_MOV32",    7)
                               ("IMAGE_REL_BASED_RISCV_LOW12S",   8)
                               ("IMAGE_REL_BASED_MIPS_JMPADDR16", 9)
                               ("IMAGE_REL_BASED_DIR64",          10);

// ----------------------------------------------------------------------------

const flag_dict WIN_CERTIFICATE_REVISIONS =
    boost::assign::map_list_of ("WIN_CERT_REVISION_1_0",          0x100)
                               ("WIN_CERT_REVISION_2_0",          0x200);

// ----------------------------------------------------------------------------

const flag_dict GLOBAL_FLAGS =
    boost::assign::map_list_of  ("FLG_STOP_ON_EXCEPTION",            0x1)
                                ("FLG_SHOW_LDR_SNAPS",               0x2)
                                ("FLG_DEBUG_INITIAL_COMMAND",        0x4)
                                ("FLG_STOP_ON_HUNG_GUI",             0x8)
                                ("FLG_HEAP_ENABLE_TAIL_CHECK",       0x10)
                                ("FLG_HEAP_ENABLE_FREE_CHECK",       0x20)
                                ("FLG_HEAP_VALIDATE_PARAMETERS",     0x40)
                                ("FLG_HEAP_VALIDATE_ALL",            0x80)
                                ("FLG_APPLICATION_VERIFIER",         0x100)
                                ("FLG_MONITOR_SILENT_PROCESS_EXIT ", 0x200)
                                ("FLG_POOL_ENABLE_TAGGING",          0x400)
                                ("FLG_HEAP_ENABLE_TAGGING",          0x800)
                                ("FLG_USER_STACK_TRACE_DB",          0x1000)
                                ("FLG_KERNEL_STACK_TRACE_DB",        0x2000)
                                ("FLG_MAINTAIN_OBJECT_TYPELIST",     0x4000)
                                ("FLG_HEAP_ENABLE_TAG_BY_DLL",       0x8000)
                                ("FLG_DISABLE_STACK_EXTENSION",      0x10000)
                                ("FLG_ENABLE_CSRDEBUG",              0x20000)
                                ("FLG_ENABLE_KDEBUG_SYMBOL_LOAD",    0x40000)
                                ("FLG_DISABLE_PAGE_KERNEL_STACKS",   0x80000)
                                ("FLG_ENABLE_SYSTEM_CRIT_BREAKS",    0x100000)
                                ("FLG_HEAP_DISABLE_COALESCING",      0x200000)
                                ("FLG_ENABLE_CLOSE_EXCEPTIONS",      0x400000)
                                ("FLG_ENABLE_EXCEPTION_LOGGING",     0x800000)
                                ("FLG_ENABLE_HANDLE_TYPE_TAGGING",   0x1000000)
                                ("FLG_HEAP_PAGE_ALLOCS",             0x2000000)
                                ("FLG_DEBUG_INITIAL_COMMAND_EX",     0x4000000)
                                ("FLG_DISABLE_DBGPRINT",             0x8000000)
                                ("FLG_CRITSEC_EVENT_CREATION",       0x10000000)
                                ("FLG_STOP_ON_UNHANDLED_EXCEPTION",  0x20000000)
                                ("FLG_ENABLE_HANDLE_EXCEPTIONS",     0x40000000)
                                ("FLG_DISABLE_PROTDLLS",             0x80000000);

// ----------------------------------------------------------------------------

const flag_dict WIN_CERTIFICATE_TYPES =
boost::assign::map_list_of  ("WIN_CERT_TYPE_X509",                   1)
                            ("WIN_CERT_TYPE_PKCS_SIGNED_DATA",       2)
                            ("WIN_CERT_TYPE_RESERVED",               3)
                            ("WIN_CERT_TYPE_PKCS1_SIGN",             4);

// ----------------------------------------------------------------------------

const flag_dict HEAP_FLAGS =
    boost::assign::map_list_of    ("HEAP_NO_SERIALIZE",              1)
                                ("HEAP_GENERATE_EXCEPTIONS",         4)
                                ("HEAP_CREATE_ENABLE_EXECUTE",       0x40000);

// ----------------------------------------------------------------------------

const flag_dict GUARD_FLAGS =
    boost::assign::map_list_of  ("IMAGE_GUARD_CF_INSTRUMENTED",                    0x00000100)
                                ("IMAGE_GUARD_CFW_INSTRUMENTED",                   0x00000200)
                                ("IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT",          0x00000400)
                                ("IMAGE_GUARD_SECURITY_COOKIE_UNUSED",             0x00000800)
                                ("IMAGE_GUARD_PROTECT_DELAYLOAD_IAT",              0x00001000)
                                ("IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION",   0x00002000)
                                ("IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT", 0x00004000)
                                ("IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION",       0x00008000)
                                ("IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT",          0x00010000)
                                ("IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK ",       0xF0000000);

// ----------------------------------------------------------------------------

// Source: https://github.com/dishather/richprint/blob/master/comp_id.txt
// The strings cannot be used as keys here are there are multiple identical values.
const std::map<int, std::string> COMP_ID_TYPE =
    boost::assign::map_list_of  (0x000, "Unmarked objects")
                                (0x001, "Total imports")
                                (0x002, "Imports")
                                (0x004, "Linker")
                                (0x006, "Resource objects")
                                (0x00A, "C objects")
                                (0x00B, "C++ objects")
                                (0x00F, "ASM objects")
                                (0x015, "C objects")
                                (0x016, "C++ objects")
                                (0x019, "Imports")
                                (0x01C, "C objects")
                                (0x01D, "C++ objects")
                                (0x03D, "Linker")
                                (0x03F, "Exports")
                                (0x040, "ASM objects")
                                (0x045, "Resource objects")
                                (0x05A, "Linker")
                                (0x05C, "Exports")
                                (0x05D, "Imports")
                                (0x05F, "C objects")
                                (0x060, "C++ objects")
                                (0x06D, "C objects")
                                (0x06E, "C++ objects")
                                (0x078, "Linker")
                                (0x07C, "Resource objects")
                                (0x07A, "Exports")
                                (0x07B, "Imports")
                                (0x07D, "ASM objects")
                                (0x083, "C objects")
                                (0x084, "C++ objects")
                                (0x091, "Resource objects")
                                (0x092, "Exports")
                                (0x093, "Imports")
                                (0x094, "Linker")
                                (0x095, "ASM objects")
                                (0x09A, "Resource objects")
                                (0x09B, "Exports")
                                (0x09C, "Imports")
                                (0x09D, "Linker")
                                (0x09E, "ASM objects")
                                (0x0AA, "C objects")
                                (0x0AB, "C++ objects")
                                (0x0C9, "Resource objects")
                                (0x0CA, "Exports")
                                (0x0CB, "Imports")
                                (0x0CC, "Linker")
                                (0x0CD, "ASM objects")
                                (0x0CE, "C objects")
                                (0x0CF, "C++ objects")
                                (0x0DB, "Resource objects")
                                (0x0DC, "Exports")
                                (0x0ED, "Imports")
                                (0x0DE, "Linker")
                                (0x0DF, "ASM objects")
                                (0x0E0, "C objects")
                                (0x0E1, "C++ objects")
                                (0x0FF, "Resource objects")
                                (0x100, "Exports")
                                (0x101, "Imports")
                                (0x102, "Linker")
                                (0x103, "ASM objects")
                                (0x104, "C objects")
                                (0x105, "C++ objects");

// ----------------------------------------------------------------------------

// Source for a few of those: https://walbourn.github.io/
const flag_dict COMP_ID_PRODID =
    boost::assign::map_list_of  ("VS97 SP3 link 5.10.7303",                    0x1c87)
                                ("VS97 SP3 cvtres 5.00.1668",                  0x0684)
                                ("VS98 cvtres build 1720",                     0x06b8)
                                ("VS98 build 8168",                            0x1fe8)
                                ("VS98 SP6 cvtres build 1736",                 0x06c7)
                                ("VC++ 6.0 SP5 imp/exp build 8447",            0x20ff)
                                ("VC++ 6.0 SP5 build 8804",                    0x2306)
                                ("VS98 SP6 build 8804",                        0x2636)
                                ("VS2002 (.NET) build 9466",                   0x24fa)
                                ("VS2003 (.NET) build 3052",                   0x0bec)
                                ("VS2003 (.NET) build 3077",                   0x0c05)
                                ("VS2003 (.NET) build 4035",                   0x0fc3)
                                ("VS2003 (.NET) SP1 build 6030",               0x178e)
                                ("VS2008 build 21022",                         0x521e)
                                ("VS2008 SP1 build 30729",                     0x7809)
                                ("VS2010 build 30319",                         0x766f)
                                ("VS2010 SP1 build 40219",                     0x9d1b)
                                ("VS2012 build 50727 / VS2005 build 50727",    0xc627)
                                ("VS2012 UPD1 build 51106",                    0xc7a2)
                                ("VS2012 UPD2 build 60315",                    0xeb9b)
                                ("VS2012 UPD3 build 60610",                    0xecc2)
                                ("VS2012 UPD4 build 61030",                    0xee66)
                                ("VS2013 build 21005",                         0x520d)
                                ("VS2013 UPD2 build 30501",                    0x7725)
                                ("VS2013 UPD3 build 30723",                    0x7803)
                                ("VS2013 UPD4 build 31101",                    0x797d)
                                ("VS2013 UPD5 build 40629",                    0x9eb5)
                                ("VS2015 build 23026",                         0x59f2)
                                ("VS2015 UPD1 build 23506",                    0x5bd2)
                                ("VS2015 UPD2 build 23918",                    0x5d6e)
                                ("VS2015 UPD3 build 24123",                    0x5e3b)
                                ("VS2015 UPD3 build 24210",                    0x5e92)
                                ("VS2015 UPD3 build 24213",                    0x5e95)
                                ("VS2015 UPD3.1 build 24215",                  0x5e97)
                                ("VS2015/2017 runtime 25008",                  0x61b0)
                                ("VS2017 v15.0 compiler 25017",                0x61b9)
                                ("VS2017 v15.2 compiler 25019",                0x61bb)
                                ("VS2017 v15.?.? build 25203",                 0x6273)
                                ("VS2015/2017 runtime 25325",                  0x62ed)
                                ("VS2017 v15.3.* compiler 25506",              0x63a2)
                                ("VS2017 v15.4.* compiler 25547",              0x63cb)
                                ("VS2015/2017 runtime 25711",                  0x646f)
                                ("VS2015/2017 runtime 25810",                  0x64d2)
                                ("VS2017 v15.5 compiler 25830",                0x64e6)
                                ("VS2017 v15.5.2 compiler 25831",              0x64e7)
                                ("VS2017 v15.5.3-4 build 25834",               0x64ea)
                                ("VS2017 v15.5.5 build 25835",                 0x64eb)
                                ("VS2017 v15.?.? build 25930",                 0x654a)
                                ("VS 2015/2017 runtime 26020",                 0x65A4)
                                ("VS2017 v15.6 compiler 26128",                0x6610)
                                ("VS2017 v15.6.3-5 compiler 26129",            0x6611)
                                ("VS2017 v15.6.6 compiler 26131",              0x6613)
                                ("VS2017 v15.6.7 compiler 26132",              0x6614)
                                ("VS 2015/2017 runtime 26405",                 0x6725)
                                ("VS2017 v15.7 compiler 26428",                0x673C)
                                ("VS2017 v15.7.2 compiler 26429",              0x673D)
                                ("VS2017 v15.7.3 compiler 26430",              0x673E)
                                ("VS2017 v15.7.4 compiler 26431",              0x673F)
                                ("VS2017 v15.7.5 compiler 26433",              0x6741)
                                ("VS 2015/2017 runtime 26706",                 0x6852)
                                ("VS2017 v15.8.1 compiler 26726",              0x6866)
                                ("VS2017 v15.8.2 compiler 26727",              0x6867)
                                ("VS2017 v15.8.3 compiler 26728",              0x6868)
                                ("VS2017 v15.8.4 compiler 26729",              0x6869)
                                ("VS2017 v15.8.5-8 compiler 26730",            0x686A)
                                ("VS2017 v15.8.9 compiler 26732",              0x686C)
                                ("VS2017 v15.9.0-1 compiler 27023",            0x698F)
                                ("VS 2015/2017 runtime 27012",                 0x6984)
                                ("VS2017 v15.9.2-3 compiler 27024",            0x6990)
                                ("VS2017 v15.9.4 compiler 27025",              0x6991)
                                ("VS2017 v15.9.5-6 compiler 27026",            0x6992)
                                ("VS2017 v15.9.7-10 compiler 27027",           0x6993)
                                ("VS2017 v15.9.11 compiler 27030",             0x6996)
                                ("VS2017 v15.9.12-13 compiler 27031",          0x6997)
                                ("VS2017 v15.9.14-15 compiler 27032",          0x6998)
                                ("VS2019 RTM compiler 27508",                  0x6B74)
                                ("VS2019 Update 1 compiler 27702",             0x6C36)
                                ("VS 2015/2017/2019 runtime 27821",            0x6CAD)
                                ("VS2019 Update 2 compiler 27905",             0x6D01)
                                ("VS2019 Update 3 compiler 28107",             0x6DCB)
    ;

// ----------------------------------------------------------------------------

const_shared_strings translate_to_flags(int value, const flag_dict& dict)
{
    auto res = boost::make_shared<std::vector<std::string> >();
    for (const auto& it : dict)
    {
        if ((value & it.second) != 0) { // The flag is present in the value
            res->push_back(it.first);
        }
    }
    return res;
}

// ----------------------------------------------------------------------------

pString translate_to_flag(unsigned int value, const flag_dict& dict)
{
    for (const auto& it : dict)
    {
        if (value == it.second) {
            return boost::make_shared<std::string>(it.first);
        }
    }
    #ifdef _DEBUG
        std::stringstream ss;
        ss << "UNKNOWN (0x" << std::hex << value << ")";
        return boost::make_shared<std::string>(ss.str());
    #else
        return boost::make_shared<std::string>("UNKNOWN");
    #endif
}

}
