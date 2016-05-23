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

#include "manape/pe.h"	// Some functions from the PE class (related to resource parsing) have been
						// implemented in this file. I know this isn't standard practice, but pe.cpp
						// was getting way too big. It made sense (at least semantically) to move
						// them here.

#include "manape/resources.h"

namespace bfs = boost::filesystem;


namespace mana
{

bool PE::_read_image_resource_directory(image_resource_directory& dir, unsigned int offset) const
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}

	if (offset)
	{
		offset = _rva_to_offset(_ioh->directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) + offset;
		if (!offset || fseek(_file_handle.get(), offset, SEEK_SET))
		{
			PRINT_ERROR << "Could not reach an IMAGE_RESOURCE_DIRECTORY." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}
	}

	unsigned int size = 2*sizeof(boost::uint32_t) + 4*sizeof(boost::uint16_t);
	dir.Entries.clear();
	if (size != fread(&dir, 1, size, _file_handle.get()))
	{
		PRINT_ERROR << "Could not read an IMAGE_RESOURCE_DIRECTORY." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}

	for (auto i = 0 ; i < dir.NumberOfIdEntries + dir.NumberOfNamedEntries ; ++i)
	{
		auto entry = boost::make_shared<image_resource_directory_entry>();
		size = 2*sizeof(boost::uint32_t);
		memset(entry.get(), 0, size);
		if (size != fread(entry.get(), 1, size, _file_handle.get()))
		{
			PRINT_ERROR << "Could not read an IMAGE_RESOURCE_DIRECTORY_ENTRY." << DEBUG_INFO_INSIDEPE << std::endl;
			return false;
		}

		// For named entries, NameOrId is a RVA to a string: retrieve it and NameOrId has high bit set to 1.
		if (entry->NameOrId & 0x80000000)
		{
			// The offset of the string is relative
			auto name_offset = _rva_to_offset(_ioh->directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)
				+ (entry->NameOrId & 0x7FFFFFFF);
			if (!name_offset || !utils::read_string_at_offset(_file_handle.get(), name_offset, entry->NameStr, true))
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

bool PE::_parse_resources()
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}
	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE))	{ // No resources.
		return true;
	}

	image_resource_directory root;
	_read_image_resource_directory(root);

	// Read Type directories
	for (std::vector<pimage_resource_directory_entry>::iterator it = root.Entries.begin() ; it != root.Entries.end() ; ++it)
	{
		image_resource_directory type;
		_read_image_resource_directory(type, (*it)->OffsetToData & 0x7FFFFFFF);

		// Read Name directory
		for (std::vector<pimage_resource_directory_entry>::iterator it2 = type.Entries.begin() ; it2 != type.Entries.end() ; ++it2)
		{
			image_resource_directory name;
			_read_image_resource_directory(name, (*it2)->OffsetToData & 0x7FFFFFFF);

			// Read the IMAGE_RESOURCE_DATA_ENTRY
			for (std::vector<pimage_resource_directory_entry>::iterator it3 = name.Entries.begin() ; it3 != name.Entries.end() ; ++it3)
			{
				image_resource_data_entry entry;
				memset(&entry, 0, sizeof(image_resource_data_entry));

				unsigned int offset = _rva_to_offset(_ioh->directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + ((*it3)->OffsetToData & 0x7FFFFFFF));
				if (!offset || fseek(_file_handle.get(), offset, SEEK_SET))
				{
					PRINT_ERROR << "Could not reach an IMAGE_RESOURCE_DATA_ENTRY." << DEBUG_INFO_INSIDEPE << std::endl;
					return false;
				}

				if (sizeof(image_resource_data_entry) != fread(&entry, 1, sizeof(image_resource_data_entry), _file_handle.get()))
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
					PRINT_WARNING << "Could not locate the section containing resource " << DEBUG_INFO_INSIDEPE;
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
					res = boost::make_shared<Resource>(type,
													   name,
													   language,
													   entry.Codepage,
													   entry.Size,
													   offset,
													   _path);
				}
				else { // No name: call the constructor with the resource ID instead.
					res = boost::make_shared<Resource>(type,
													  id,
													  language,
													  entry.Codepage,
													  entry.Size,
													  offset,
													  _path);
				}

				_resource_table.push_back(res);
			}
		}
	}

	return true;
}

// ----------------------------------------------------------------------------

shared_bytes Resource::get_raw_data() const
{
	auto res = boost::make_shared<std::vector<boost::uint8_t> >();

	FILE* f = _reach_data();
	unsigned int read_bytes;
	if (f == nullptr) {
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
	if (f != nullptr) {
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
DECLSPEC pString Resource::interpret_as()
{
	if (_type != "RT_MANIFEST")
	{
		PRINT_WARNING << "Resources of type " << _type << "cannot be interpreted as std::strings." << DEBUG_INFO << std::endl;
		return boost::make_shared<std::string>();
	}
	shared_bytes manifest_bytes = get_raw_data();
	return boost::make_shared<std::string>(manifest_bytes->begin(), manifest_bytes->end());
}

// ----------------------------------------------------------------------------

template<>
DECLSPEC const_shared_wstrings Resource::interpret_as()
{
	auto res = boost::make_shared<std::vector<std::wstring> >();
	if (_type != "RT_STRING")
	{
		PRINT_WARNING << "Resources of type " << _type << " cannot be interpreted as vectors of strings." << DEBUG_INFO << std::endl;
		return res;
	}

	FILE* f = _reach_data();
	if (f == nullptr) {
		goto END;
	}

	// RT_STRING resources are made of 16 contiguous "unicode" strings.
	for (int i = 0; i < 16; ++i) {
		res->push_back(utils::read_prefixed_unicode_wstring(f));
	}

	END:
	if (f != nullptr) {
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

	auto res = boost::make_shared<bitmap>();
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
	if (f == nullptr) {
		return pgroup_icon_directory();
	}

	auto res = boost::make_shared<group_icon_directory>();
	unsigned int size = sizeof(boost::uint16_t) * 3;
	if (size != fread(res.get(), 1, size, f))
	{
		res.reset();
		goto END;
	}

	for (unsigned int i = 0; i < res->Count; ++i)
	{
		auto entry = boost::make_shared<group_icon_directory_entry>();

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
	fclose(f);
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
	if (f == nullptr) {
		return pversion_info();
	}

	auto res = boost::make_shared<version_info>();
	unsigned int bytes_read; // Is calculated by calling ftell before and after reading a structure, and keeping the difference.
	unsigned int bytes_remaining;
	unsigned int padding;
	unsigned int language;
	std::stringstream ss;

	// We are going to read a lot of structures which look like a version info header.
	// They will all be read into this variable, one at a time.
	auto current_structure = boost::make_shared<vs_version_info_header>();
	if (!parse_version_info_header(res->Header, f))
	{
		res.reset();
		goto END;
	}
	res->Value = boost::make_shared<fixed_file_info>();
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
		auto p = boost::make_shared<string_pair>(current_structure->Key, value);
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
	if (f == nullptr) { // File has moved, or is already in use.
		return nullptr;
	}

	if (!_offset_in_file || fseek(f, _offset_in_file, SEEK_SET))
	{
		// Offset is invalid
		fclose(f);
		return nullptr;
	}

	return f;
}

// ----------------------------------------------------------------------------

std::vector<boost::uint8_t> reconstruct_icon(pgroup_icon_directory directory, const std::vector<pResource>& resources)
{
	std::vector<boost::uint8_t> res;

	if (directory == nullptr) {
		return res;
	}

	unsigned int header_size = 3 * sizeof(boost::uint16_t) + directory->Count * sizeof(group_icon_directory_entry);
	res.resize(header_size);
	memcpy(&res[0], directory.get(), 3 * sizeof(boost::uint16_t));

	for (int i = 0; i < directory->Count; ++i)
	{
		// Locate the RT_ICON with a matching ID.
		pResource icon = pResource();
		for (auto it = resources.begin(); it != resources.end(); ++it)
		{
			if ((*it)->get_id() == directory->Entries[i]->Id)
			{
				icon = *it;
				break;
			}
		}
		if (icon == nullptr)
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
		unsigned long size_fix = res.size();
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

/**
 * @brief   Function which writes bytes to a given file. Created to prevent code
 * duplication between extract and icon_extract.
 *
 * @param   const boost::filesystem::path& destination The path to the file to write.
 * @param   std::vector<boost::uint8_t> data The data to write.
 *
 * @return  Whether the file creation succeeded.
 */
bool write_data_to_file(const boost::filesystem::path& destination, std::vector<boost::uint8_t> data)
{
    FILE* f = fopen(destination.string().c_str(), "wb+");
    if (f == nullptr)
    {
        PRINT_ERROR << "Could not open " << destination.string() << "." << DEBUG_INFO << std::endl;
        return false;
    }
    if (data.size() != fwrite(&data[0], 1, data.size(), f))
    {
        fclose(f);
        PRINT_ERROR << "Could not write all the bytes for " << destination.string() << "." << DEBUG_INFO << std::endl;
        return false;
    }

    fclose(f);
    return true;
}

// ----------------------------------------------------------------------------

bool Resource::extract(const boost::filesystem::path& destination)
{
    shared_bytes data;
	if (_type == "RT_GROUP_ICON" || _type == "RT_GROUP_CURSOR")
    {
        PRINT_WARNING << "Use icon_extract to properly recreate icons." << std::endl;
        data = get_raw_data();
	}
    else if (_type == "RT_BITMAP")
    {
        unsigned int header_size = 2 * sizeof(boost::uint8_t) + 2 * sizeof(boost::uint16_t) + 2 * sizeof(boost::uint32_t);
        auto bmp = interpret_as<pbitmap>();
        if (bmp == nullptr)
        {
            PRINT_ERROR << "Bitmap " << _name << " is malformed!" << std::endl;
            return false;
        }

        // Copy the BMP header
        boost::shared_ptr<std::vector<boost::uint8_t> > bmp_bytes(new std::vector<boost::uint8_t>(header_size));
        memcpy(&bmp_bytes->at(0), bmp.get(), header_size);
        // Copy the image bytes.
        bmp_bytes->insert(bmp_bytes->end(), bmp->data.begin(), bmp->data.end());
        data = bmp_bytes;
    }
    else if (_type == "RT_STRING")
    {
        // RT_STRINGs are written immediately to the file instead of trying to reconstruct
        // an original byte stream.
        auto strings = interpret_as<const_shared_wstrings>();
        if (strings->size() == 0) {
            return true;
        }

		FILE* out = fopen(destination.string().c_str(), "a+,ccs=UTF-8");
		for (auto it2 = strings->begin(); it2 != strings->end(); ++it2)
		{
			if (*it2 != L"")
			{
				fwrite(it2->c_str(), wcslen(it2->c_str()) * sizeof(wchar_t), 1, out);
				fwrite(L"\n", 1, 2, out);
			}
		}
		fclose(out);
        return true;
    }
    else {
        data = get_raw_data();
    }

    if (data == nullptr || data->size() == 0)
    {
        PRINT_WARNING << "Resource " << _name << " is empty!"  << DEBUG_INFO << std::endl;
        return true;
    }

    return write_data_to_file(destination, *data);
}

// ----------------------------------------------------------------------------

bool Resource::icon_extract(const boost::filesystem::path& destination,
                            const std::vector<pResource>& resources)
{
    std::vector<boost::uint8_t> data;
    if (_type != "RT_GROUP_ICON" && _type != "RT_GROUP_CURSOR")
    {
        PRINT_WARNING << "Called icon_extract on a non-icon resource!" << std::endl;
        return extract(destination);
    }
    data = reconstruct_icon(interpret_as<pgroup_icon_directory>(), resources);
    return write_data_to_file(destination, data);
}

} // !namespace mana
