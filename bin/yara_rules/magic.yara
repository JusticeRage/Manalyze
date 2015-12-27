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

rule Bitmap_graphic
{
    meta:
        extension = ".bmp"
        description = "Bitmap graphic"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 42 4D }

    condition:
        $a at 0
}
rule Java_Class_File
{
    meta:
        extension = ".class"
        description = "Java Class File"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { CA FE BA BE }

    condition:
        $a at 0
}
rule Java_Archive
{
    meta:
        extension = ".jar"
        description = "Java Archive"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 50 4B 03 04 14 00 08 00 08 00 }
        $b = { 5F 27 A8 89 }

    condition:
        $a at 0 or $b at 0
}
rule JPEG_graphic_file
{
    meta:
        extension = ".jpg"
        description = "JPEG graphic file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { FF D8 FF }

    condition:
        $a at 0
}
rule JPEG_2000_graphic_file
{
    meta:
        extension = ".jp2"
        description = "JPEG 2000 graphic file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 00 00 00 0C 6A 50 20 20 0D 0A }

    condition:
        $a at 0
}
rule GIF_graphic_file
{
    meta:
        extension = ".gif"
        description = "GIF graphic file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 47 49 46 38 }

    condition:
        $a at 0
}
rule TIF_graphic_file
{
    meta:
        extension = ".tif"
        description = "TIF graphic file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 49 20 49 }
        $b = { 49 49 2A 00 }

    condition:
        $a at 0 or $b at 0
}
rule PNG_graphic_file
{
    meta:
        extension = ".png"
        description = "PNG graphic file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 89 50 4E 47 0D 0A 1A 0A }

    condition:
        $a at 0
}
rule Photoshop_Graphics
{
    meta:
        extension = ".psd"
        description = "Photoshop Graphics"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 38 42 50 53 }

    condition:
        $a at 0
}
rule Windows_Meta_File
{
    meta:
        extension = ".wmf"
        description = "Windows Meta File"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { D7 CD C6 9A }
        $b = { 01 00 09 00 00 03 }

    condition:
        $a at 0 or $b at 0
}
rule MIDI_file
{
    meta:
        extension = ".mid"
        description = "MIDI file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 4D 54 68 64 }

    condition:
        $a at 0
}
rule Icon_file
{
    meta:
        extension = ".ico"
        description = "Icon file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 00 00 01 00 }

    condition:
        $a at 0
}
rule Cursor_file
{
    meta:
        extension = ".cur"
        description = "Cursor file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 00 00 02 00 }

    condition:
        $a at 0
}
rule MP3_file_with_ID3_identity_tag
{
    meta:
        extension = ".mp3"
        description = "MP3 file with ID3 identity tag"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 49 44 33 }

    condition:
        $a at 0
}
rule Flash_Shockwave
{
    meta:
        extension = ".swf"
        description = "Flash Shockwave"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 46 57 53 }

    condition:
        $a at 0
}
rule Flash_Video
{
    meta:
        extension = ".flv"
        description = "Flash Video"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 46 4C 56 01 }

    condition:
        $a at 0
}
rule Adobe_Flash_shared_object_file
{
    meta:
        extension = ".sol"
        description = "Adobe Flash shared object file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 00 BF }

    condition:
        $a at 0
}
rule MP4_video_file
{
    meta:
        extension = ".mp4"
        description = "MP4 video file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 00 00 00 18 66 74 79 70 6D 70 34 32 }

    condition:
        $a at 0
}
rule M4A_video_file
{
    meta:
        extension = ".m4a"
        description = "M4A video file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 00 00 00 1C 66 74 79 70 4D 53 4E 56 01 29 00 46 4D 53 4E 56 6D 70 34 32 }

    condition:
        $a at 0
}
rule MOV_video_file
{
    meta:
        extension = ".mov"
        description = "MOV video file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 6D 6F 6F 76 }

    condition:
        $a at 0
}
rule QuickTime_movie_file
{
    meta:
        extension = ".mov"
        description = "QuickTime movie file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 66 74 79 70 71 74 20 20 }

    condition:
        $a at 4
}
rule MPEG_4_video_QuickTime_file
{
    meta:
        extension = ".m4v"
        description = "MPEG-4 video/QuickTime file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 66 74 79 70 6D 70 34 32 }

    condition:
        $a at 4
}
rule Windows_Video_file
{
    meta:
        extension = ".wmv"
        description = "Windows Video file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 30 26 B2 75 8E 66 CF }

    condition:
        $a at 0
}
rule GZip
{
    meta:
        extension = ".gz"
        description = "GZip Compressed Archive"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 1F 8B 08 }

    condition:
        $a at 0
}
rule bzip2_compressed_archive
{
    meta:
        extension = ".bz2"
        description = "bzip2 compressed archive"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 42 5A 68 }

    condition:
        $a at 0
}
rule Tar_file
{
    meta:
        extension = ".tar"
        description = "Tar file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 75 73 74 61 72 }

    condition:
        $a at 0
}
rule Tape_Archive_file
{
    meta:
        extension = ".tar"
        description = "Tape Archive file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 75 73 74 61 72 }

    condition:
        $a at 257
}
rule Compressed_tape_archive_file
{
    meta:
        extension = ".tar.z"
        description = "Compressed tape archive file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 1F 9D }
        $b = { 1F A0 }

    condition:
        $a at 0 or $b at 0
}
rule LZH_Compressed_archive_file
{
    meta:
        extension = ".lzh"
        description = "LZH Compressed archive file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 2D 6C 68 }

    condition:
        $a at 2
}
rule _7_Zip_compressed_file
{
    meta:
        extension = ".7z"
        description = "7-Zip compressed file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 37 7A BC AF 27 1C }

    condition:
        $a at 0
}
rule Microsoft_COFF_object_file
{
    meta:
        extension = ".obj"
        description = "Microsoft COFF object file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 4C 01 }

    condition:
        $a at 0
}
rule CAB_Installer_file
{
    meta:
        extension = ".cab"
        description = "CAB Installer file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 4D 53 43 46 }
        $b = { 49 53 63 28 }

    condition:
        $a at 0 or $b at 0
}
rule Microsoft_C___debugging_symbols_file
{
    meta:
        extension = ".pdb"
        description = "Microsoft C++ debugging symbols file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 4D 69 63 72 6F 73 6F 66 74 20 43 2F 43 2B 2B 20 }

    condition:
        $a at 0
}
rule Help_file
{
    meta:
        extension = ".hlp"
        description = "Help file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 3F 5F 03 00 }

    condition:
        $a at 0
}
rule VMWare_Disk_file
{
    meta:
        extension = ".vmdk"
        description = "VMWare Disk file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 4B 44 4D 56 }

    condition:
        $a at 0
}
rule VMware_BIOS_state_file
{
    meta:
        extension = ".nvram"
        description = "VMware BIOS state file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 4D 52 56 4E }

    condition:
        $a at 0
}
rule Outlook_Post_Office_file
{
    meta:
        extension = ".pst"
        description = "Outlook Post Office file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 21 42 44 4E 42 }

    condition:
        $a at 0
}
rule PDF_Document
{
    meta:
        extension = ".pdf"
        description = "PDF Document"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 25 50 44 46 }

    condition:
        $a in (0..1024)
}
rule Word_Document
{
    meta:
        extension = ".doc"
        description = "Word Document"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
		$rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$worddoc = "WordDocument" wide
		$msworddoc = "MSWordDoc" nocase

	condition:
		$rootentry and ($worddoc or $msworddoc)
}
rule RTF_Document
{
    meta:
        extension = ".rtf"
        description = "RTF Document"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 7B 5C 72 74 66 31 }

    condition:
        $a at 0
}
rule Excel_Document
{
    meta:
        extension = ".xls"
        description = "Excel Document"

    strings:
		$rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$workbook = "Workbook" wide nocase
		$msexcel = "Microsoft Excel" nocase

	condition:
		all of them
}
rule PowerPoint_Document
{
    meta:
        extension = ".ppt"
        description = "PowerPoint Document"

    strings:
		$pptdoc = "PowerPoint Document" wide nocase
		$rootentry = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		all of them
}
rule Microsoft_Office_Open_XML_Format
{
    meta:
        extension = ".docx"
        description = "Microsoft Office Open XML Format"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 50 4B 03 04 14 00 06 00 }

    condition:
        $a at 0
}
rule Microsoft_Database
{
    meta:
        extension = ".mdb"
        description = "Microsoft Database"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 53 74 61 6E 64 61 72 64 20 4A 65 74 }
        $b = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 }

    condition:
        $a at 0 or $b at 0
}
rule Microsoft_SQL_Server_2000_database
{
    meta:
        extension = ".mdf"
        description = "Microsoft SQL Server 2000 database"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 01 0F 00 00 }

    condition:
        $a at 0
}
rule Microsoft_Access_2007_file
{
    meta:
        extension = ".accdb"
        description = "Microsoft Access 2007 file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42 }

    condition:
        $a at 0
}
rule Microsoft_Money_file
{
    meta:
        extension = ".mny"
        description = "Microsoft Money file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 00 01 00 00 4D 53 49 53 41 4D 20 44 61 74 61 62 61 73 65 }

    condition:
        $a at 0
}
rule Postcript_File
{
    meta:
        extension = ".ps"
        description = "Postcript File"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 25 21 }

    condition:
        $a at 0
}
rule EPS_File
{
    meta:
        extension = ".eps"
        description = "EPS File"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 25 21 50 53 2D 41 64 6F 62 65 2D 33 2E 30 20 45 50 53 46 2D 33 20 30 }

    condition:
        $a at 0
}
rule SLN_File
{
    meta:
        extension = ".sln"
        description = "SLN File"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 4D 69 63 72 6F 73 6F 66 74 20 56 69 73 75 61 6C 20 53 74 75 64 69 6F 20 53 6F 6C 75 74 69 6F 6E 20 46 69 6C 65 }

    condition:
        $a at 0
}
rule XCF_Gimp_file_structure
{
    meta:
        extension = ".xcf"
        description = "XCF Gimp file structure"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 67 69 6D 70 20 78 63 66 20 76 }

    condition:
        $a at 0
}
rule TrueType_font_file
{
    meta:
        extension = ".ttf"
        description = "TrueType font file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 00 01 00 00 00 }

    condition:
        $a at 0
}
rule Mujahideen_Secrets_2_encrypted_file
{
    meta:
        extension = ".enc"
        description = "Mujahideen Secrets 2 encrypted file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 00 5C 41 B1 FF }

    condition:
        $a at 0
}
rule AES_Crypt_file_format
{
    meta:
        extension = ".aes"
        description = "AES Crypt file format"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 41 45 53 }

    condition:
        $a at 0
}
rule _1Password_4_Cloud_Keychain_encrypted_attachment
{
    meta:
        extension = ".attachment"
        description = "1Password 4 Cloud Keychain encrypted attachment"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 4F 50 43 4C 44 41 54 }

    condition:
        $a at 0
}
rule Alcohol_120__CD_image
{
    meta:
        extension = ".mdf"
        description = "Alcohol 120% CD image"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 00 FF FF FF FF FF FF FF FF FF FF 00 00 02 00 01 }

    condition:
        $a at 0
}
rule PAK_Compressed_archive_file
{
    meta:
        extension = ".pak"
        description = "PAK Compressed archive file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 1A 0B }

    condition:
        $a at 0
}
rule WebM_video_file
{
    meta:
        extension = ".webm"
        description = "WebM video file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 1A 45 DF A3 }

    condition:
        $a at 0
}
rule Matroska_stream_file
{
    meta:
        extension = ".mkv"
        description = "Matroska stream file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 1A 45 DF A3 93 42 82 88 6D 61 74 72 6F 73 6B 61 }

    condition:
        $a at 0
}
rule AVI_Resource_Interchange_File_Format
{
    meta:
        extension = ".avi"
        description = "AVI Resource Interchange File Format"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 41 56 49 20 4C 49 53 54 }

    condition:
        $a at 0
}
rule CD_DA_Resource_Interchange_File_Format
{
    meta:
        extension = ".cda"
        description = "CD-DA Resource Interchange File Format"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 43 44 44 41 66 6D 74 20 }

    condition:
        $a at 0
}
rule RMI_Resource_Interchange_File_Format
{
    meta:
        extension = ".rmi"
        description = "RMI Resource Interchange File Format"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 52 4D 49 44 64 61 74 61 }

    condition:
        $a at 0
}
rule WAV_Resource_Interchange_File_Format
{
    meta:
        extension = ".wav"
        description = "WAV Resource Interchange File Format"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 57 41 56 45 66 6D 74 20 }

    condition:
        $a at 0
}
rule Ogg_Vorbis_Codec_compressed_Multimedia_file
{
    meta:
        extension = ".ogg"
        description = "Ogg Vorbis Codec compressed Multimedia file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 4F 67 67 53 00 02 00 00 00 00 00 00 00 00 }

    condition:
        $a at 0
}
rule Free_Lossless_Audio_Codec_file
{
    meta:
        extension = ".flac"
        description = "Free Lossless Audio Codec file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 66 4C 61 43 00 00 00 22 }

    condition:
        $a at 0
}
rule AOL_and_AIM_buddy_list_file
{
    meta:
        extension = ".bag"
        description = "AOL and AIM buddy list file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 41 4F 4C 20 46 65 65 64 62 61 67 }

    condition:
        $a at 0
}
rule vCard_file
{
    meta:
        extension = ".vcf"
        description = "vCard file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 42 45 47 49 4E 3A 56 43 41 52 44 0D 0A }


    condition:
        $a at 0
}
rule Palmpilot_resource_file
{
    meta:
        extension = ".prc"
        description = "Palmpilot resource file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 42 4F 4F 4B 4D 4F 42 49 }

    condition:
        $a at 0
}
rule Microsoft_Reader_eBook_file
{
    meta:
        extension = ".lit"
        description = "Microsoft Reader eBook file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 49 54 4F 4C 49 54 4C 53 }

    condition:
        $a at 0
}
rule Open_Publication_Structure_eBook_file
{
    meta:
        extension = ".epub"
        description = "Open Publication Structure eBook file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 50 4B 03 04 0A 00 02 00 }

    condition:
        $a at 0
}
rule Microsoft_Compiled_HTML_Help_File
{
    meta:
        extension = ".chm"
        description = "Microsoft Compiled HTML Help File"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 49 54 53 46 }

    condition:
        $a at 0
}
rule Windows_shortcut_file
{
    meta:
        extension = ".lnk"
        description = "Windows shortcut file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 4C 00 00 00 01 14 02 00 }

    condition:
        $a at 0
}
rule Windows_64_bit_memory_dump
{
    meta:
        extension = ".dmp"
        description = "Windows 64-bit memory dump"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 50 41 47 45 44 55 36 34 }

    condition:
        $a at 0
}
rule Windows_memory_dump__dmp
{
    meta:
        extension = ".dmp"
        description = "Windows memory dump"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 41 47 45 44 55 4D 50 }

    condition:
        $a at 0
}
rule PKSFX_self_extracting_executable_compressed_file
{
    meta:
        extension = ".zip"
        description = "PKSFX self-extracting executable compressed file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 50 4B 53 70 58 }

    condition:
        $a at 526
}
rule WinRAR_compressed_archive_file
{
    meta:
        extension = ".rar"
        description = "WinRAR compressed archive file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 52 61 72 21 1A 07 00 }

    condition:
        $a at 0
}
rule WinZip_compressed_archive
{
    meta:
        extension = ".zip"
        description = "WinZip compressed archive"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 57 69 6E 5A 69 70 }

    condition:
        $a at 0
}
rule ARJ_compressed_archive_file
{
    meta:
        extension = ".arj"
        description = "ARJ compressed archive file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 60 EA }

    condition:
        $a at 0
}
rule XZ_archive_file
{
    meta:
        extension = ".xz"
        description = "XZ archive file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { FD 37 7A 58 5A 00 }

    condition:
        $a at 0
}
rule Dalvik_executable_file
{
    meta:
        extension = ".dex"
        description = "Dalvik executable file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 64 65 78 0A 30 30 39 00 }

    condition:
        $a at 0
}
rule E_mail
{
    meta:
        extension = ".eml"
        description = "E-mail"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 52 65 74 75 72 6E 2D 50 61 74 68 3A 20 }
        $b = { 58 2D }

    condition:
        $a at 0 or $b at 0
}
rule Visual_C_PreCompiled_header_file
{
    meta:
        extension = ".pch"
        description = "Visual C PreCompiled header file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 56 43 50 43 48 30 }

    condition:
        $a at 0
}
rule WinAmp_Playlist_file
{
    meta:
        extension = ".pls"
        description = "WinAmp Playlist file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 5B 70 6C 61 79 6C 69 73 74 5D }

    condition:
        $a at 0
}
rule Yara_Compiled_Rule
{
    meta:
        extension = ".yarac"
        description = "Yara Compiled Rule"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = "YARA"

    condition:
        $a at 0
}
rule Zip
{
    meta:
        extension = ".zip"
        description = "Zip Compressed Archive"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 50 4B 03 04 }

    condition:
        $a at 0
}
rule Executable_file
{
    meta:
        extension = ".exe"
        description = "PE Executable"

    condition:
		uint16(0) == 0x5A4D and
		uint32(uint32(0x3C)) == 0x00004550
}
rule Windows_animated_cursor
{
    meta:
        extension = ".ani"
        description = "Windows animated cursor"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 52 49 46 46 }

    condition:
        $a at 0
}
rule Executable_and_Linking_Format_executable_file__Linux_Unix_
{
    meta:
        extension = ".elf"
        description = "Executable and Linking Format executable file (Linux/Unix)"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { 7F 45 4C 46 }

    condition:
        $a at 0
}
rule tcpdump_capture_file
{
    meta:
        extension = ".pcap"
        description = "tcpdump capture file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { A1 B2 C3 D4 }
        $b = { A1 B2 CD 34 }

    condition:
        $a at 0 or $b at 0
}
rule Java_Cryptography_Extension_keystore_file
{
    meta:
        extension = ".jceks"
        description = "Java Cryptography Extension keystore file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { CE CE CE CE }

    condition:
        $a at 0
}
rule JavaKeyStore_file
{
    meta:
        extension = ".jks"
        description = "JavaKeyStore file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { FE ED FE ED }

    condition:
        $a at 0
}
rule Apple_IOS_apps
{
    meta:
        extension = ".class"
        description = "Apple IOS apps"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { CE FA ED FE }

    condition:
        $a at 0
}
rule RedHat_Package_Manager_file__rpm
{
    meta:
        extension = "ED"
        description = "RedHat Package Manager file .rpm"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { AB EE DB }

    condition:
        $a at 0
}
rule Driver_file
{
    meta:
        extension = ".sys"
        description = "Driver file"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { FF 4B 45 59 42 20 20 20 }

    condition:
        $a at 0
}
rule OLE_Compound_File
{
    meta:
        extension = ".ole"
        description = "OLE Compound File"
        author = "Ivan Kwiatkowski (@JusticeRage)"

    strings:
        $a = { D0 CF 11 E0 A1 B1 1A E1 }

    condition:
        $a at 0
}
