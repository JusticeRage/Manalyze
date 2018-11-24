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

namespace mana
{

bool PE::_read_image_resource_directory(image_resource_directory& dir, unsigned int offset) const
{
	if (!_ioh || _file_handle == nullptr) {
		return false;
	}

	if (offset)
	{
		offset = rva_to_offset(_ioh->directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) + offset;
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

	// Do not parse corrupted tables as it will take an extremely long time.
	// If Characteristics is not 0 (which it should always be according to the specification) and the number of entries is
	// unusually high, assume that the file is corrupted.
	if (dir.NumberOfIdEntries + dir.NumberOfNamedEntries > 0x100 && dir.Characteristics != 0)
	{
		PRINT_ERROR << "The PE's resource section is invalid or has been manually modified. Resources will not be parsed." << DEBUG_INFO_INSIDEPE << std::endl;
		return false;
	}
	else if (dir.Characteristics != 0) {
		PRINT_WARNING << "An IMAGE_RESOURCE_DIRECTORY's characteristics should always be 0. The PE may have been manually edited." << DEBUG_INFO_INSIDEPE << std::endl;
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
			auto name_offset = rva_to_offset(_ioh->directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)
				+ (entry->NameOrId & 0x7FFFFFFF);
			if (!name_offset || !utils::read_string_at_offset(_file_handle.get(), name_offset, entry->NameStr, true))
			{
				PRINT_ERROR << "Could not read an IMAGE_RESOURCE_DIRECTORY_ENTRY's name." << DEBUG_INFO_INSIDEPE << std::endl;
				return false;
			}
		}

		// Immediately reject obvious bogus entries.
		if ((entry->OffsetToData & 0x7FFFFFFF) > _file_size)
		{
			PRINT_WARNING << "Ignored an invalid IMAGE_RESOURCE_DIRECTORY_ENTRY." << DEBUG_INFO_INSIDEPE << std::endl;
			continue;
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
	if (!_read_image_resource_directory(root)) {
		return false;
	}

	// Read Type directories
	for (std::vector<pimage_resource_directory_entry>::iterator it = root.Entries.begin() ; it != root.Entries.end() ; ++it)
	{
		image_resource_directory type;
		if (! _read_image_resource_directory(type, (*it)->OffsetToData & 0x7FFFFFFF)) {
			continue;
		}

		// Read Name directory
		for (std::vector<pimage_resource_directory_entry>::iterator it2 = type.Entries.begin() ; it2 != type.Entries.end() ; ++it2)
		{
			image_resource_directory name;
			if (!_read_image_resource_directory(name, (*it2)->OffsetToData & 0x7FFFFFFF)) {
				continue;
			}

			// Read the IMAGE_RESOURCE_DATA_ENTRY
			for (std::vector<pimage_resource_directory_entry>::iterator it3 = name.Entries.begin() ; it3 != name.Entries.end() ; ++it3)
			{
				image_resource_data_entry entry;
				memset(&entry, 0, sizeof(image_resource_data_entry));

				unsigned int offset = rva_to_offset(_ioh->directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + ((*it3)->OffsetToData & 0x7FFFFFFF));
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

				if (entry.Size > _file_size)
				{
					// TODO: Logging feature which stops spamming stderr after a message has been shown 10 times?
					// The warning below is commented out as it tends to be displayed way too many times for offending binaries.
					// PRINT_WARNING << "Ignored an invalid IMAGE_RESOURCE_DATA_ENTRY" << DEBUG_INFO_INSIDEPE << std::endl;
					continue;
				}

				// Flatten the resource tree.
				std::string r_name;
				std::string r_type;
				std::string r_language;
				int id = 0;

				// Translate resource type.
				if ((*it)->NameOrId & 0x80000000) {// NameOrId is an offset to a string, we already recovered it
					r_type = (*it)->NameStr;
				}
				else { // Otherwise, it's a MAKERESOURCEINT constant.
					r_type = *nt::translate_to_flag((*it)->NameOrId, nt::RESOURCE_TYPES);
				}

				// Translate resource name
				if ((*it2)->NameOrId & 0x80000000) {
					r_name = (*it2)->NameStr;
				}
				else {
					id = (*it2)->NameOrId;
				}

				// Translate the language.
				if ((*it3)->NameOrId & 0x80000000) {
					r_language = (*it3)->NameStr;
				}
				else {
					r_language = *nt::translate_to_flag((*it3)->NameOrId, nt::LANG_IDS);
				}

				offset = rva_to_offset(entry.OffsetToData);
				if (!offset)
				{
					PRINT_WARNING << "Could not locate the section containing resource " << DEBUG_INFO_INSIDEPE;
					if (id) {
						std::cerr << id;
					}
					else {
						std::cerr << r_name;
					}
					std::cerr << ". Trying to use the RVA as an offset..." << DEBUG_INFO_INSIDEPE << std::endl;
					offset = entry.OffsetToData;
				}
				pResource res;
				if (entry.Size == 0)
				{
					if (r_name != "") {
						PRINT_WARNING << "Resource " << r_name << " has a size of 0!" << DEBUG_INFO_INSIDEPE << std::endl;
					}
					else {
						PRINT_WARNING << "Resource " << id << " has a size of 0!" << DEBUG_INFO_INSIDEPE << std::endl;
					}
					continue;
				}

				// Sanity check: verify that no resource is already pointing to the given offset.
				bool is_malformed = false;
				for (auto it4 = _resource_table.begin() ; it4 != _resource_table.end() ; ++it4)
				{
					if (*it4 != nullptr && (*it4)->get_offset() == offset && (*it4)->get_size() == entry.Size)
					{
						PRINT_WARNING << "The PE contains duplicate resources. It was almost certainly crafted manually." 
									  << DEBUG_INFO_INSIDEPE << std::endl;
						is_malformed = true;
						break;
					}
				}
				if (is_malformed) {  // Duplicate resource. Do not add it again.
					continue;
				}

				if (r_name != "")
				{
					res = boost::make_shared<Resource>(r_type,
													   r_name,
													   r_language,
													   entry.Codepage,
													   entry.Size,
													   name.TimeDateStamp,
													   offset,
													   _path);
				}
				else { // No name: call the constructor with the resource ID instead.
					res = boost::make_shared<Resource>(r_type,
													   id,
													   r_language,
													   entry.Codepage,
													   entry.Size,
													   name.TimeDateStamp,
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
	size_t read_bytes;
	if (f == nullptr) {
		goto END;
	}

	// Linux doesn't throw std::bad_alloc, instead it has OOM Killer shutdown the process.
	// This workaround prevents Manalyze from crashing by bounding how much memory can be requested.
	#ifdef BOOST_POSIX_API
		struct stat st;
		stat(_path_to_pe.c_str(), &st);
		if (_size > st.st_size)
		{
			PRINT_ERROR << "Resource " << *get_name() << " is bigger than the PE. Not trying to load it in memory."
						<< DEBUG_INFO << std::endl;
			return res;
		}
	#endif

	try {
		res->resize(_size);
	}
	catch (const std::exception& e)
	{
		PRINT_ERROR << "Failed to allocate enough space for resource " << *get_name() << "! (" << e.what() << ")"
					<< DEBUG_INFO << std::endl;
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
DECLSPEC const_shared_strings Resource::interpret_as()
{
	auto res = boost::make_shared<std::vector<std::string> >();
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
	for (int i = 0; i < 16; ++i)
	{
		res->push_back(utils::read_prefixed_unicode_string(f));
		std::vector<boost::uint8_t> utf8result;
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
	boost::uint16_t bit_count;
	memcpy(&dib_header_size, &(res->data[0]), sizeof(boost::uint32_t)); // DIB header size is located at offset 0.
	memcpy(&bit_count, &(res->data[14]), sizeof(boost::uint16_t));
	memcpy(&colors_used, &(res->data[32]), sizeof(boost::uint32_t));


	if (colors_used == 0 && bit_count != 32 && bit_count != 24)	{
		colors_used = 1 << bit_count;
	}

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
			fread(&(entry->Width), 1, sizeof(boost::uint8_t), f);
			fseek(f, 1, SEEK_CUR);
			fread(&(entry->Height), 1, sizeof(boost::uint8_t), f);
            entry->Height /= 2; // For some reason, twice the actual height is stored here.
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
	if (!ss.fail()) {
		res->Language = *nt::translate_to_flag((language >> 16) & 0xFFFF, nt::LANG_IDS);
	}
	else
	{
		PRINT_WARNING << "A language ID could not be translated (" << std::hex << res->Language << ")!" << std::endl;
		res->Language = "UNKNOWN";
	}

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

	// Sanity check.
	if (directory->Count > resources.size())
	{
		PRINT_ERROR << "The number of ICON_DIRECTORY_ENTRIES is bigger than the number of resources in the file." << DEBUG_INFO << std::endl;
		return std::vector<boost::uint8_t>();
	}

	boost::uint32_t header_size = 3 * sizeof(boost::uint16_t) + directory->Count * sizeof(group_icon_directory_entry);
	try {
		res.resize(header_size);
	}
	catch (const std::bad_alloc)
	{
		PRINT_ERROR << "Could not allocate enough memory to reconstruct an icon. This PE may have been manually modified." << DEBUG_INFO << std::endl;
		return std::vector<boost::uint8_t>();
	}
	memcpy(&res[0], directory.get(), 3 * sizeof(boost::uint16_t));

	for (int i = 0; i < directory->Count; ++i)
	{
		// Locate the RT_ICON with a matching ID.
		pResource icon = pResource();
		for (auto it = resources.begin(); it != resources.end(); ++it)
		{
            auto type = (*it)->get_type();
            // Because there can be duplicate resource IDs, only consider the ones exhibiting the right type.
			if ((*it)->get_id() == directory->Entries[i]->Id && type &&
                ((*type == "RT_ICON" && directory->Type == 1) || (*type == "RT_CURSOR" && directory->Type == 2)))
			{
				icon = *it;
				break;
			}
		}
		if (icon == nullptr)
		{
			PRINT_ERROR << "Could not locate RT_ICON with ID " << directory->Entries[i]->Id << "!" << DEBUG_INFO << std::endl;
			return std::vector<boost::uint8_t>();
		}

		shared_bytes icon_bytes = icon->get_raw_data();
		memcpy(&res[3 * sizeof(boost::uint16_t) + i * sizeof(group_icon_directory_entry)],
			   directory->Entries[i].get(),
			   sizeof(group_icon_directory_entry) - sizeof(boost::uint32_t)); // Don't copy the last field.
		// Fix the icon_directory_entry with the offset in the file instead of a RT_ICON id
		size_t size_fix = res.size();
		memcpy(&res[3 * sizeof(boost::uint16_t) + (i+1) * sizeof(group_icon_directory_entry) - sizeof(boost::uint32_t)],
			   &size_fix,
			   sizeof(boost::uint32_t));
		// Append the icon bytes at the end of the data
		if (directory->Type == 1) { // General case for icons
			res.insert(res.end(), icon_bytes->begin(), icon_bytes->end());
		}
		else if (icon_bytes->size() > 4 && directory->Entries[i]->BytesInRes > 4) // Cursors have a "hotspot" structure that we have to discard to create a valid ico.
        {
			res.insert(res.end(), icon_bytes->begin() + 2 * sizeof(boost::uint16_t), icon_bytes->end());
            // Remove 4 from the size to account for this suppression
            int new_size = directory->Entries[i]->BytesInRes - 4;
            memcpy(&res[3 * sizeof(boost::uint16_t) + i * sizeof(group_icon_directory_entry) + 8], &new_size, 4);
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
	if (data.size() == 0) {
		return true;
	}

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
        auto strings = interpret_as<const_shared_strings>();
        if (strings->size() == 0) {
            return true;
        }

		FILE* out = fopen(destination.string().c_str(), "a+");

		if(out == nullptr) {
			PRINT_ERROR << "Opening file " << destination.string().c_str() << " failed!" << std::endl;
			return false;
		}

		for (auto it2 = strings->begin(); it2 != strings->end(); ++it2)
		{
			if (*it2 != "")
			{
				fwrite(it2->c_str(), it2->size(), 1, out);
				fwrite("\n", 1, 1, out);
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
    if (_type != "RT_GROUP_ICON" && _type != "RT_GROUP_CURSOR")
    {
        PRINT_WARNING << "Called icon_extract on a non-icon resource!" << std::endl;
        return extract(destination);
    }
    auto data = reconstruct_icon(interpret_as<pgroup_icon_directory>(), resources);
	if (data.empty())
	{
		PRINT_WARNING << "Resource " << _id << " is empty!" << DEBUG_INFO << std::endl;
		return true;
	}

    return write_data_to_file(destination, data);
}

} // !namespace mana
