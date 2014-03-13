#include "pe.h"
#include "resources.h" // Helper functions used only in the context of resource parsing.

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
				presource res = presource(new resource);
				res->OffsetToData = entry.OffsetToData;
				res->Codepage = entry.Codepage;
				res->Size = entry.Size;

				// Translate resource type.
				if ((*it)->NameOrId & 0x80000000) {// NameOrId is an offset to a string, we already recovered it
					res->Type = (*it)->NameStr;
				}
				else { // Otherwise, it's a MAKERESOURCEINT constant.
					res->Type = nt::translate_to_flag((*it)->NameOrId, nt::RESOURCE_TYPES);
				}

				// Translate resource name
				if ((*it2)->NameOrId & 0x80000000) {
					res->Name = (*it2)->NameStr;
				}
				else 
				{
					std::stringstream ss;
					ss << "#" << (*it2)->NameOrId; // Use the ID as a name.
					res->Name = ss.str();
				}

				// Translate the language.
				if ((*it3)->NameOrId & 0x80000000) {
					res->Language = (*it3)->NameStr;
				}
				else {
					res->Language = nt::translate_to_flag((*it3)->NameOrId, nt::LANG_IDS);
				}

				_resource_table.push_back(res);
			}
		}
	}

	return true;
}

} // !namespace sg