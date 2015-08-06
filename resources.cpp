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

#include "pe.h" // Some functions from the PE class (related to resource parsing) have been
				// implemented in this file. I know this isn't standard practice, but pe.cpp
				// was getting way too big. It made sense (at least semantically) to move
				// them here.

#include "resources.h"

namespace bfs = boost::filesystem;


namespace sg
{

// Initialize the Yara wrapper used by resource objects
yara::pYara Resource::_yara = yara::Yara::create();

bool PE::_read_image_resource_directory(image_resource_directory& dir, FILE* f, unsigned int offset)
{
	if (!_ioh) {
		return false;
	}

	if (offset)
	{
		offset = _rva_to_offset(_ioh->directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) + offset;
		if (!offset || fseek(f, offset, SEEK_SET))
		{
			PRINT_ERROR << "Could not reach an IMAGE_RESOURCE_DIRECTORY." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
	}

	unsigned int size = 2*sizeof(boost::uint32_t) + 4*sizeof(boost::uint16_t);
	dir.Entries.clear();
	if (size != fread(&dir, 1, size, f))
	{
		PRINT_ERROR << "Could not read an IMAGE_RESOURCE_DIRECTORY." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	for (int i = 0 ; i < dir.NumberOfIdEntries + dir.NumberOfNamedEntries ; ++i)
	{
		pimage_resource_directory_entry entry = pimage_resource_directory_entry(new image_resource_directory_entry);
		size = 2*sizeof(boost::uint32_t);
		memset(entry.get(), 0, size);
		if (size != fread(entry.get(), 1, size, f))
		{
			PRINT_ERROR << "Could not read an IMAGE_RESOURCE_DIRECTORY_ENTRY." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		// For named entries, NameOrId is a RVA to a string: retrieve it and NameOrId has high bit set to 1.
		if (entry->NameOrId & 0x80000000)
		{
			// The offset of the string is relative
			unsigned int offset = _rva_to_offset(_ioh->directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)
				+ (entry->NameOrId & 0x7FFFFFFF);
			if (!offset || !utils::read_string_at_offset(f, offset, entry->NameStr, true))
			{
				PRINT_ERROR << "Could not read an IMAGE_RESOURCE_DIRECTORY_ENTRY's name." << DEBUG_INFO_INSIDEPE << std::endl;
				return false;
			}
		}

		dir.Entries.push_back(entry);
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_resources(FILE* f)
{
	if (!_ioh) {
		return false;
	}
	if (!_reach_directory(f, IMAGE_DIRECTORY_ENTRY_RESOURCE))	{ // No resources.
		return true;
	}

	image_resource_directory root;
	_read_image_resource_directory(root, f);

	// Read Type directories
	for (std::vector<pimage_resource_directory_entry>::iterator it = root.Entries.begin() ; it != root.Entries.end() ; ++it)
	{
		image_resource_directory type;
		_read_image_resource_directory(type, f, (*it)->OffsetToData & 0x7FFFFFFF);

		// Read Name directory
		for (std::vector<pimage_resource_directory_entry>::iterator it2 = type.Entries.begin() ; it2 != type.Entries.end() ; ++it2)
		{
			image_resource_directory name;
			_read_image_resource_directory(name, f, (*it2)->OffsetToData & 0x7FFFFFFF);

			// Read the IMAGE_RESOURCE_DATA_ENTRY
			for (std::vector<pimage_resource_directory_entry>::iterator it3 = name.Entries.begin() ; it3 != name.Entries.end() ; ++it3)
			{
				image_resource_data_entry entry;
				memset(&entry, 0, sizeof(image_resource_data_entry));

				unsigned int offset = _rva_to_offset(_ioh->directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + ((*it3)->OffsetToData & 0x7FFFFFFF));
				if (!offset || fseek(f, offset, SEEK_SET))
				{
					PRINT_ERROR << "Could not reach an IMAGE_RESOURCE_DATA_ENTRY." << DEBUG_INFO_INSIDEPE << std::endl;
					return false;
				}

				if (sizeof(image_resource_data_entry) != fread(&entry, 1, sizeof(image_resource_data_entry), f))
				{
					PRINT_ERROR << "Could not read an IMAGE_RESOURCE_DATA_ENTRY." << DEBUG_INFO_INSIDEPE << std::endl;
					return false;
				}

				// Flatten the resource tree.
				std::string name;
				std::string type;
				std::string language;
				int id = 0;

				// Translate resource type.
				if ((*it)->NameOrId & 0x80000000) {// NameOrId is an offset to a string, we already recovered it
					type = (*it)->NameStr;
				}
				else { // Otherwise, it's a MAKERESOURCEINT constant.
					type = *nt::translate_to_flag((*it)->NameOrId, nt::RESOURCE_TYPES);
				}

				// Translate resource name
				if ((*it2)->NameOrId & 0x80000000) {
					name = (*it2)->NameStr;
				}
				else {
					id = (*it2)->NameOrId;
				}

				// Translate the language.
				if ((*it3)->NameOrId & 0x80000000) {
					language = (*it3)->NameStr;
				}
				else {
					language = *nt::translate_to_flag((*it3)->NameOrId, nt::LANG_IDS);
				}

				offset = _rva_to_offset(entry.OffsetToData);
				if (!offset)
				{
					PRINT_WARNING << "Could not locate the section containing resource ";
					if (id) {
						std::cerr << id;
					}
					else {
						std::cerr << name;
					}
					std::cerr << ". Trying to use the RVA as an offset..." << DEBUG_INFO_INSIDEPE << std::endl;
					offset = entry.OffsetToData;
				}
				pResource res;
				if (entry.Size == 0)
				{
					if (name != "") {
						PRINT_WARNING << "Resource " << name << " has a size of 0!" << DEBUG_INFO_INSIDEPE << std::endl;
					}
					else {
						PRINT_WARNING << "Resource " << id << " has a size of 0!" << DEBUG_INFO_INSIDEPE << std::endl;
					}
					continue;
				}
				if (name != "")
				{
					res = pResource(new Resource(type,
												 name,
												 language,
												 entry.Codepage,
												 entry.Size,
												 offset,
												 _path));
				}
				else { // No name: call the constructor with the resource ID instead.
					res = pResource(new Resource(type,
												 id,
												 language,
												 entry.Codepage,
												 entry.Size,
												 offset,
												 _path));
				}

				_resource_table.push_back(res);
			}
		}
	}

	return true;
}

// ----------------------------------------------------------------------------

bool PE::_parse_debug(FILE* f)
{
	if (!_ioh) {
		return false;
	}
	if (!_reach_directory(f, IMAGE_DIRECTORY_ENTRY_DEBUG))	{ // No debug information.
		return true;
	}

	unsigned int size = 6*sizeof(boost::uint32_t) + 2*sizeof(boost::uint16_t);
	unsigned int number_of_entries = _ioh->directories[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / size;

	for (unsigned int i = 0 ; i < number_of_entries ; ++i)
	{
		pdebug_directory_entry debug = pdebug_directory_entry(new debug_directory_entry);
		memset(debug.get(), 0, size);
		if (size != fread(debug.get(), 1, size, f))
		{
			PRINT_ERROR << "Could not read the DEBUG_DIRECTORY_ENTRY" << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		// VC++ Debug information
		if (debug->Type == nt::DEBUG_TYPES.at("IMAGE_DEBUG_TYPE_CODEVIEW"))
		{
			pdb_info pdb;
			unsigned int pdb_size = 2*sizeof(boost::uint32_t) + 16*sizeof(boost::uint8_t);
			memset(&pdb, 0, pdb_size);

			unsigned int saved_offset = ftell(f);
			fseek(f, debug->PointerToRawData, SEEK_SET);
			if (pdb_size != fread(&pdb, 1, pdb_size, f) ||
				(pdb.Signature != 0x53445352 && pdb.Signature != 0x3031424E)) // Signature: "RSDS" or "NB10"
			{
				PRINT_ERROR << "Could not read PDB file information of invalid magic number." << DEBUG_INFO_INSIDEPE << std::endl;
				return false;
			}
			pdb.PdbFileName = utils::read_ascii_string(f); // Not optimal, but it'll help if I decide to
														   // further parse these debug sub-structures.
			debug->Filename = pdb.PdbFileName;
			fseek(f, saved_offset, SEEK_SET);
		}
		else if (debug->Type == nt::DEBUG_TYPES.at("IMAGE_DEBUG_TYPE_MISC"))
		{
			image_debug_misc misc;
			unsigned int misc_size = 2*sizeof(boost::uint32_t) + 4*sizeof(boost::uint8_t);
			memset(&misc, 1, misc_size);
			unsigned int saved_offset = ftell(f);
			fseek(f, debug->PointerToRawData, SEEK_SET);
			if (misc_size != fread(&misc, 1, misc_size, f))
			{
				PRINT_ERROR << "Could not read DBG file information" << DEBUG_INFO_INSIDEPE << std::endl;
				return false;
			}
			switch (misc.Unicode)
			{
				case 1:
					misc.DbgFile = utils::read_unicode_string(f, misc.Length - misc_size);
					break;
				case 0:
					misc.DbgFile = utils::read_ascii_string(f, misc.Length - misc_size);
					break;
			}
			debug->Filename = misc.DbgFile;
			fseek(f, saved_offset, SEEK_SET);
		}
		_debug_entries.push_back(debug);
	}

	return true;
}

// ----------------------------------------------------------------------------

shared_bytes Resource::get_raw_data() const
{
	boost::shared_ptr<std::vector<boost::uint8_t> > res(new std::vector<boost::uint8_t>());

	FILE* f = _reach_data();
	unsigned int read_bytes;
	if (f == NULL) {
		goto END;
	}

	try {
		res->resize(_size);
	}
	catch (const std::exception& e)
	{
		PRINT_ERROR << "Failed to allocate enough space for resource " << *get_name() << "! (" << e.what() << ")"
			<< DEBUG_INFO << std::endl;
		res->resize(0);
		return res;
	}
	read_bytes = fread(&(*res)[0], 1, _size, f);
	if (read_bytes != _size) { // We got less bytes than expected: reduce the vector's size.
		res->resize(read_bytes);
	}

	END:
	if (f != NULL) {
		fclose(f);
	}
	return res;
}

// ----------------------------------------------------------------------------

bool parse_version_info_header(vs_version_info_header& header, FILE* f)
{
	memset(&header, 0, 3 * sizeof(boost::uint16_t));
	if (3*sizeof(boost::uint16_t) != fread(&header, 1, 3*sizeof(boost::uint16_t), f))
	{
		PRINT_ERROR << "Could not read a VS_VERSION_INFO header!" << DEBUG_INFO << std::endl;
		return false;
	}
	header.Key = utils::read_unicode_string(f);
	unsigned int padding = ftell(f) % 4; // Next structure is 4-bytes aligned
	return !fseek(f, padding, SEEK_CUR);
}

// ----------------------------------------------------------------------------

template<>
std::string Resource::interpret_as()
{
	if (_type != "RT_MANIFEST")
	{
		PRINT_WARNING << "Resources of type " << _type << "cannot be interpreted as std::strings." << DEBUG_INFO << std::endl;
		return "";
	}
	shared_bytes manifest_bytes = get_raw_data();
	return std::string(manifest_bytes->begin(), manifest_bytes->end());
}

// ----------------------------------------------------------------------------

template<>
std::vector<std::string> Resource::interpret_as()
{
	std::vector<std::string> res;
	if (_type != "RT_STRING")
	{
		PRINT_WARNING << "Resources of type " << _type << " cannot be interpreted as vectors of strings." << DEBUG_INFO << std::endl;
		return res;
	}

	FILE* f = _reach_data();
	if (f == NULL) {
		goto END;
	}

	// RT_STRING resources are made of 16 contiguous "unicode" strings.
	for (int i = 0; i < 16; ++i) {
		res.push_back(utils::read_prefixed_unicode_string(f));
	}

	END:
	if (f != NULL) {
		fclose(f);
	}
	return res;
}

// ----------------------------------------------------------------------------

template<>
DECLSPEC pbitmap Resource::interpret_as()
{
	if (_type != "RT_BITMAP") {
		return pbitmap();
	}

	pbitmap res = pbitmap(new bitmap);
	unsigned int header_size = 14;
	res->Magic[0] = 'B';
	res->Magic[1] = 'M';
	res->Reserved1 = 0;
	res->Reserved2 = 0;
	res->data = *get_raw_data();
	res->Size = res->data.size() + header_size;

	// Calculate the offset to the raw data.
	if (res->data.size() < 36) { // Not enough bytes to make a valid BMP
		return pbitmap();
	}
	boost::uint32_t dib_header_size = 0;
	boost::uint32_t colors_used = 0;
	memcpy(&dib_header_size, &(res->data[0]), sizeof(boost::uint32_t)); // DIB header size is located at offset 0.
	memcpy(&colors_used, &(res->data[32]), sizeof(boost::uint32_t));

	res->OffsetToData = header_size + dib_header_size + 4*colors_used;
	return res;
}

// ----------------------------------------------------------------------------

template<>
DECLSPEC pgroup_icon_directory Resource::interpret_as()
{
	if (_type != "RT_GROUP_ICON" && _type != "RT_GROUP_CURSOR") {
		return pgroup_icon_directory();
	}
	FILE* f = _reach_data();
	if (f == NULL) {
		return pgroup_icon_directory();
	}

	pgroup_icon_directory res = pgroup_icon_directory(new group_icon_directory);
	unsigned int size = sizeof(boost::uint16_t) * 3;
	if (size != fread(res.get(), 1, size, f))
	{
		res.reset();
		goto END;
	}

	for (unsigned int i = 0; i < res->Count; ++i)
	{
		pgroup_icon_directory_entry entry = pgroup_icon_directory_entry(new group_icon_directory_entry);

		memset(entry.get(), 0, sizeof(group_icon_directory_entry));

		if (_type == "RT_GROUP_ICON")
		{
			// sizeof(group_icon_directory_entry) - 2 to compensate the field that was changed to boost::uint32.
			// See the comment in the structure for more information.
			if (sizeof(group_icon_directory_entry)-2 != fread(entry.get(), 1, sizeof(group_icon_directory_entry) - 2, f))
			{
				res.reset();
				goto END;
			}
		}
		else // Cursors have a different structure. Adapt it to a .ico.
		{
			// I know I am casting bytes to shorts here. I'm not proud of it.
			fread(&(entry->Width), 1, sizeof(boost::uint8_t), f);
			fseek(f, 1, SEEK_CUR);
			fread(&(entry->Height), 1, sizeof(boost::uint8_t), f);
			fseek(f, 1, SEEK_CUR);
			fread(&(entry->Planes), 1, sizeof(boost::uint16_t), f);
			fread(&(entry->BitCount), 1, sizeof(boost::uint16_t), f);
			fread(&(entry->BytesInRes), 1, sizeof(boost::uint32_t), f);
			fread(&(entry->Id), 1, sizeof(boost::uint16_t), f);
			if (ferror(f) || feof(f))
			{
				res.reset();
				goto END;
			}
		}

		res->Entries.push_back(entry);
	}

	END:
	if (f != NULL) {
		fclose(f);
	}
	return res;
}

// ----------------------------------------------------------------------------

template<>
DECLSPEC pversion_info Resource::interpret_as()
{
	if (_type != "RT_VERSION") {
		return pversion_info();
	}

	FILE* f = _reach_data();
	if (f == NULL) {
		return pversion_info();
	}

	pversion_info res = pversion_info(new version_info);
	unsigned int bytes_read; // Is calculated by calling ftell before and after reading a structure, and keeping the difference.
	unsigned int bytes_remaining;
	unsigned int padding;
	unsigned int language;
	std::stringstream ss;

	// We are going to read a lot of structures which look like a version info header.
	// They will all be read into this variable, one at a time.
	pvs_version_info_header current_structure = pvs_version_info_header(new vs_version_info_header);
	if (!parse_version_info_header(res->Header, f))
	{
		res.reset();
		goto END;
	}
	res->Value = pfixed_file_info(new fixed_file_info);
	memset(res->Value.get(), 0, sizeof(fixed_file_info));

	// 0xFEEF04BD is a magic located at the beginning of the VS_FIXED_FILE_INFO structure.
	if (sizeof(fixed_file_info) != fread(res->Value.get(), 1, sizeof(fixed_file_info), f) || res->Value->Signature != 0xfeef04bd)
	{
		PRINT_ERROR << "Could not read a VS_FIXED_FILE_INFO!" << DEBUG_INFO << std::endl;
		res.reset();
		goto END;
	}

	bytes_read = ftell(f);
	if (!parse_version_info_header(*current_structure, f))
	{
		res.reset();
		goto END;
	}

	// This (uninteresting) VAR_FILE_INFO structure may be located before the STRING_FILE_INFO we're after.
	// In this case, just skip it.
	if (current_structure->Key == "VarFileInfo")
	{
		bytes_read = ftell(f) - bytes_read;
		fseek(f, current_structure->Length - bytes_read, SEEK_CUR);
		if (!parse_version_info_header(*current_structure, f))
		{
			res.reset();
			goto END;
		}
	}

	if (current_structure->Key != "StringFileInfo")
	{
		PRINT_ERROR << "StringFileInfo expected, read " << current_structure->Key << " instead." << DEBUG_INFO << std::endl;
		res.reset();
		goto END;
	}

	// We don't need the contents of StringFileInfo. Replace them with the next structure.
	bytes_read = ftell(f);
	if (!parse_version_info_header(*current_structure, f))
	{
		res.reset();
		goto END;
	}

	// In the file, the language information is an int stored into a "unicode" string.
	ss << std::hex << current_structure->Key;
	ss >> language;
	res->Language = *nt::translate_to_flag((language >> 16) & 0xFFFF, nt::LANG_IDS);

	bytes_read = ftell(f) - bytes_read;
	if (current_structure->Length < bytes_read)
	{
		PRINT_ERROR << "The StringTableInfo has an invalid size." << DEBUG_INFO << std::endl;
		res.reset();
		goto END;
	}
	bytes_remaining = current_structure->Length - bytes_read;

	// Read the StringTable
	while (bytes_remaining > 0)
	{
		bytes_read = ftell(f);
		if (!parse_version_info_header(*current_structure, f))
		{
			res.reset();
			goto END;
		}
		std::string value;
		// If the string is null, there won't even be a null terminator.
		if (ftell(f) - bytes_read < current_structure->Length) {
			value = utils::read_unicode_string(f);
		}
		bytes_read = ftell(f) - bytes_read;
		if (bytes_remaining < bytes_read)
		{
			bytes_remaining = 0;
			PRINT_WARNING << bytes_read - bytes_remaining << " excess bytes have been read from a StringFileInfo!"
				<< DEBUG_INFO << std::endl;
		}
		else {
			bytes_remaining -= bytes_read;
		}

		// Add the key/value to our internal representation
		ppair p = ppair(new std::pair<std::string, std::string>(current_structure->Key, value));
		res->StringTable.push_back(p);

		// The next structure is 4byte aligned.
		padding = ftell(f) % 4;
		if (padding)
		{
			fseek(f, padding, SEEK_CUR);
			// The last padding doesn't seem to be included in the length given by the structure.
			// So if there are no more remaining bytes, don't stop here. (Otherwise, integer underflow.)
			if (padding < bytes_remaining) {
				bytes_remaining -= padding;
			}
			else {
				bytes_remaining = 0;
			}
		}
	}

	/*
	   Theoretically, there may be a VarFileInfo (with translation information) structure afterwards
	   if it wasn't encountered before).
	   In practice, I find it irrelevant to my interests, and supporting it would increase the
	   complexity of the version_info structure. If you *absolutely* need this for some reason,
	   let me know.
	*/

	END:
	fclose(f);
	return res;
}

// ----------------------------------------------------------------------------

template<>
DECLSPEC shared_bytes Resource::interpret_as() {
	return get_raw_data();
}

// ----------------------------------------------------------------------------

FILE* Resource::_reach_data() const
{
	FILE* f = fopen(_path_to_pe.c_str(), "rb");
	if (f == NULL) { // File has moved, or is already in use.
		return NULL;
	}

	if (!_offset_in_file || fseek(f, _offset_in_file, SEEK_SET))
	{
		// Offset is invalid
		fclose(f);
		return NULL;
	}

	return f;
}

// ----------------------------------------------------------------------------

std::vector<boost::uint8_t> reconstruct_icon(pgroup_icon_directory directory, const std::vector<pResource>& resources)
{
	std::vector<boost::uint8_t> res;

	if (directory == NULL) {
		return res;
	}

	unsigned int header_size = 3 * sizeof(boost::uint16_t) + directory->Count * sizeof(group_icon_directory_entry);
	res.resize(header_size);
	memcpy(&res[0], directory.get(), 3 * sizeof(boost::uint16_t));

	for (int i = 0; i < directory->Count; ++i)
	{
		// Locate the RT_ICON with a matching ID.
		pResource icon = pResource();
		for (std::vector<pResource>::const_iterator it = resources.begin(); it != resources.end(); ++it)
		{
			if ((*it)->get_id() == directory->Entries[i]->Id)
			{
				icon = *it;
				break;
			}
		}
		if (icon == NULL)
		{
			PRINT_ERROR << "Could not locate RT_ICON with ID " << directory->Entries[i]->Id << "!" << DEBUG_INFO << std::endl;
			res.clear();
			return res;
		}

		shared_bytes icon_bytes = icon->get_raw_data();
		memcpy(&res[3 * sizeof(boost::uint16_t) + i * sizeof(group_icon_directory_entry)],
			   directory->Entries[i].get(),
			   sizeof(group_icon_directory_entry) - sizeof(boost::uint32_t)); // Don't copy the last field.
		// Fix the icon_directory_entry with the offset in the file instead of a RT_ICON id
		unsigned int size_fix = res.size();
		memcpy(&res[3 * sizeof(boost::uint16_t) + (i+1) * sizeof(group_icon_directory_entry) - sizeof(boost::uint32_t)],
			   &size_fix,
			   sizeof(boost::uint32_t));
		// Append the icon bytes at the end of the data
		if (directory->Type == 1) { // General case for icons
			res.insert(res.end(), icon_bytes->begin(), icon_bytes->end());
		}
		else if (icon_bytes->size() > 2 * sizeof(boost::uint16_t)) { // Cursors have a "hotspot" structure that we have to discard to create a valid ico.
			res.insert(res.end(), icon_bytes->begin() + 2 * sizeof(boost::uint16_t), icon_bytes->end());
		}
		else { // Invalid cursor.
			res.clear();
		}
	}

	return res;
}

// ----------------------------------------------------------------------------

bool PE::extract_resources(const std::string& destination_folder)
{
	if (!bfs::exists(destination_folder) && !bfs::create_directory(destination_folder))
	{
		PRINT_ERROR << "Could not create directory " << destination_folder << "." << DEBUG_INFO << std::endl;
		return false;
	}

	std::string base = bfs::basename(_path);
	FILE* f;
	for (std::vector<pResource>::iterator it = _resource_table.begin() ; it != _resource_table.end() ; ++it)
	{
		bfs::path destination_file;
		std::stringstream ss;
		std::vector<boost::uint8_t> data;
		if (*(*it)->get_type() == "RT_GROUP_ICON" || *(*it)->get_type() == "RT_GROUP_CURSOR")
		{
			ss << base << "_" << (*it)->get_id() << "_" << *(*it)->get_type() << ".ico";
			data = reconstruct_icon((*it)->interpret_as<pgroup_icon_directory>(), _resource_table);
		}
		else if (*(*it)->get_type() == "RT_MANIFEST")
		{
			ss << base << "_" << (*it)->get_id() << "_RT_MANIFEST.xml";
			data = *(*it)->get_raw_data();
		}
		else if (*(*it)->get_type() == "RT_BITMAP")
		{
			ss << base << "_" << (*it)->get_id() << "_RT_BITMAP.bmp";
			unsigned int header_size = 2 * sizeof(boost::uint8_t) + 2 * sizeof(boost::uint16_t) + 2 * sizeof(boost::uint32_t);
			pbitmap bmp = (*it)->interpret_as<pbitmap>();
			if (bmp == NULL)
			{
				PRINT_ERROR << "Bitmap " << *(*it)->get_name() << " is malformed!" << std::endl;
				continue;
			}

			// Copy the BMP header
			data.resize(header_size, 0);
			memcpy(&data[0], bmp.get(), header_size);
			// Copy the image bytes.
			data.insert(data.end(), bmp->data.begin(), bmp->data.end());
		}
		else if (*(*it)->get_type() == "RT_ICON" || *(*it)->get_type() == "RT_CURSOR" || *(*it)->get_type() == "RT_VERSION") {
			// Ignore the following resource types: we don't want to extract them.
			continue;
		}
		else if (*(*it)->get_type() == "RT_STRING")
		{
			// Append all the strings to the same file.
			std::vector<std::string> strings = (*it)->interpret_as<std::vector<std::string> >();
			if (strings.size() == 0) {
				continue;
			}

			destination_file = bfs::path(destination_folder) / bfs::path(base + "_RT_STRINGs.txt");
			FILE* f = fopen(destination_file.string().c_str(), "a+");
			if (f == NULL)
			{
				PRINT_ERROR << "Could not open/create " << destination_file << "!" << std::endl;
				continue;
			}

			for (std::vector<std::string>::iterator it = strings.begin(); it != strings.end(); ++it)
			{
				if ((*it) != "")
				{
					fwrite(it->c_str(), 1, it->size(), f);
					fputc('\n', f);
				}
			}
			fclose(f);
			continue;
		}
		else // General case
		{
			ss << base << "_";
			if (*(*it)->get_name() != "") {
				ss << *(*it)->get_name();
			}
			else {
				ss << (*it)->get_id();
			}

			// Try to guess the file extension
			yara::const_matches m = (*it)->detect_filetype();
			if (m && m->size() > 0) {
				ss << "_" << *(*it)->get_type() << m->at(0)->operator[]("extension");
			}
			else {
				ss << "_" << *(*it)->get_type() << ".raw";
			}

			data = *(*it)->get_raw_data();
		}

		if (data.size() == 0)
		{
			PRINT_WARNING << "Resource " << *(*it)->get_name() << " is empty!"  << DEBUG_INFO << std::endl;
			continue;
		}

		destination_file = bfs::path(destination_folder) / bfs::path(ss.str());
		f = fopen(destination_file.string().c_str(), "wb+");
		if (f == NULL)
		{
			PRINT_ERROR << "Could not open " << destination_file << "." << DEBUG_INFO << std::endl;
			return false;
		}
		if (data.size() != fwrite(&data[0], 1, data.size(), f))
		{
			fclose(f);
			PRINT_ERROR << "Could not write all the bytes for " << destination_file << "." << DEBUG_INFO << std::endl;
			return false;
		}

		fclose(f);
	}
	return true;
}

// ----------------------------------------------------------------------------

yara::const_matches Resource::detect_filetype()
{
	if (_yara->load_rules("yara_rules/magic.yara"))
	{
		shared_bytes bytes = get_raw_data();
		return _yara->scan_bytes(*bytes);
	}
	else {
		return yara::matches();
	}
}

} // !namespace sg
