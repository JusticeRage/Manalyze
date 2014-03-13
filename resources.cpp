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

#include "pe.h" // Some functions from the PE class (related to resource parsing) have been
				// implemented in this file. I know this isn't standard practice, but pe.cpp
				// was getting way too big. It made sense (at least semantically) to move
				// them here.

#include "resources.h"

namespace sg 
{

bool PE::read_image_resource_directory(image_resource_directory& dir, FILE* f, unsigned int offset)
{
	if (offset)
	{
		offset = _rva_to_offset(_ioh.directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) + offset;
		if (!offset || fseek(f, offset, SEEK_SET))
		{
			std::cout << "[!] Error: Could not reach an IMAGE_RESOURCE_DIRECTORY." << std::endl;
			return false;
		}
	}

	unsigned int size = 2*sizeof(boost::uint32_t) + 4*sizeof(boost::uint16_t);
	dir.Entries.clear();
	if (size != fread(&dir, 1, size, f))
	{
		std::cout << "[!] Error: Could not read an IMAGE_RESOURCE_DIRECTORY." << std::endl;
		return false;
	}

	for (int i = 0 ; i < dir.NumberOfIdEntries + dir.NumberOfNamedEntries ; ++i)
	{
		pimage_resource_directory_entry entry = pimage_resource_directory_entry(new image_resource_directory_entry);
		size = 2*sizeof(boost::uint32_t);
		memset(entry.get(), 0, size);
		if (size != fread(entry.get(), 1, size, f))
		{
			std::cout << "[!] Error: Could not read an IMAGE_RESOURCE_DIRECTORY_ENTRY." << std::endl;
			return false;
		}

		// For named entries, NameOrId is a RVA to a string: retrieve it and NameOrId has high bit set to 1.
		if (entry->NameOrId & 0x80000000) 
		{
			// The offset of the string is relative 
			unsigned int offset = _rva_to_offset(_ioh.directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) 
				+ (entry->NameOrId & 0x7FFFFFFF);
			if (!offset || !utils::read_string_at_offset(f, offset, entry->NameStr, true))
			{
				std::cout << "[!] Error: Could not read an IMAGE_RESOURCE_DIRECTORY_ENTRY's name." << std::endl;
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
	if (!_reach_directory(f, IMAGE_DIRECTORY_ENTRY_RESOURCE))	{ // No resources.
		return true;
	}

	image_resource_directory root;
	read_image_resource_directory(root, f);

	// Read Type directories
	for (std::vector<pimage_resource_directory_entry>::iterator it = root.Entries.begin() ; it != root.Entries.end() ; ++it)
	{
		image_resource_directory type;
		read_image_resource_directory(type, f, (*it)->OffsetToData & 0x7FFFFFFF);

		// Read Name directory
		for (std::vector<pimage_resource_directory_entry>::iterator it2 = type.Entries.begin() ; it2 != type.Entries.end() ; ++it2)
		{
			image_resource_directory name;
			read_image_resource_directory(name, f, (*it2)->OffsetToData & 0x7FFFFFFF);

			// Read the IMAGE_RESOURCE_DATA_ENTRY
			for (std::vector<pimage_resource_directory_entry>::iterator it3 = name.Entries.begin() ; it3 != name.Entries.end() ; ++it3)
			{
				image_resource_data_entry entry;
				memset(&entry, 0, sizeof(image_resource_data_entry));

				unsigned int offset = _rva_to_offset(_ioh.directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress + ((*it3)->OffsetToData & 0x7FFFFFFF));
				if (!offset || fseek(f, offset, SEEK_SET))
				{
					std::cout << "[!] Error: Could not reach an IMAGE_RESOURCE_DATA_ENTRY." << std::endl;
					return false;
				}

				if (sizeof(image_resource_data_entry) != fread(&entry, 1, sizeof(image_resource_data_entry), f))
				{
					std::cout << "[!] Error: Could not read an IMAGE_RESOURCE_DATA_ENTRY." << std::endl;
					return false;
				}

				// Flatten the resource tree.
				std::string name;
				std::string type;
				std::string language;

				// Translate resource type.
				if ((*it)->NameOrId & 0x80000000) {// NameOrId is an offset to a string, we already recovered it
					type = (*it)->NameStr;
				}
				else { // Otherwise, it's a MAKERESOURCEINT constant.
					type = nt::translate_to_flag((*it)->NameOrId, nt::RESOURCE_TYPES);
				}

				// Translate resource name
				if ((*it2)->NameOrId & 0x80000000) {
					name = (*it2)->NameStr;
				}
				else 
				{
					std::stringstream ss;
					ss << "#" << (*it2)->NameOrId; // Use the ID as a name.
					name = ss.str();
				}

				// Translate the language.
				if ((*it3)->NameOrId & 0x80000000) {
					language = (*it3)->NameStr;
				}
				else {
					language = nt::translate_to_flag((*it3)->NameOrId, nt::LANG_IDS);
				}

				offset = _rva_to_offset(entry.OffsetToData);
				pResource res = pResource(new Resource(type,
													   name,
													   language,
													   entry.Codepage,
													   entry.Size,
													   offset,
													   get_path()));

				_resource_table.push_back(res);
			}
		}
	}

	return true;
}

// ----------------------------------------------------------------------------

std::vector<boost::uint8_t> Resource::get_raw_data()
{
	std::vector<boost::uint8_t> res = std::vector<boost::uint8_t>();
	
	FILE* f = _reach_data();
	if (f == NULL) {
		goto END;
	}
	
	res.resize(_size);
	unsigned int read_bytes = fread(&res[0], 1, _size, f);
	if (read_bytes != _size) { // We got less bytes than expected: reduce the vector's size.
		res.resize(read_bytes);
	}

	END:
	if (f != NULL) {
		fclose(f);
	}
	return res;
}

// ----------------------------------------------------------------------------

template<>
std::string Resource::interpret_as()
{
	if (_type != "RT_MANIFEST") {
		return "Resources of type " + _type + " cannot be interpreted as std::strings.";
	}
	std::vector<boost::uint8_t> manifest_bytes = get_raw_data();
	return std::string(manifest_bytes.begin(), manifest_bytes.end());
}

// ----------------------------------------------------------------------------

template<>
std::vector<std::string> Resource::interpret_as()
{
	std::vector<std::string> res;
	if (_type != "RT_STRING") {
		return res;
	}

	FILE* f = _reach_data();
	if (f == NULL) {
		goto END;
	}

	// RT_STRING resources are made of 16 contiguous "unicode" strings.
	for (int i = 0; i < 16; ++i) {
		res.push_back(utils::read_unicode_string(f));
	}

	END:
	if (f != NULL) {
		fclose(f);
	}
	return res;
}

FILE* Resource::_reach_data()
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
// Below this: specific parsing for specific resource types (RT_*)
// ----------------------------------------------------------------------------

/*std::string Resource::as_rt_manifest(const std::vector<boost::uint8_t>& bytes) {
	return std::string(bytes.begin(), bytes.end());
}

// ----------------------------------------------------------------------------

std::vector<std::string> parse_rt_string(const std::vector<boost::uint8_t>& bytes)
{
	unsigned int cursor = 0;
	std::vector<std::string> res();
	for (int i = 0 ; i < 16 ; ++i)
	{
		res.push_back(utils::read_unicode_string(f))
	}
}*/


} // !namespace sg