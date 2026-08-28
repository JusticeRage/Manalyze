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

#include <limits>

namespace mana
{

namespace {
	constexpr size_t MAX_RESOURCE_DIRECTORY_ENTRIES = 0x100;
	constexpr size_t MAX_RESOURCE_ENTRIES = 10000;
	constexpr std::uint64_t IMAGE_RESOURCE_DIRECTORY_SIZE = 16;
	constexpr std::uint64_t IMAGE_RESOURCE_DATA_ENTRY_SIZE = 16;

	bool fits_file_range(std::uint64_t offset, std::uint64_t size,
		std::uint64_t file_size)
	{
		return offset <= file_size && size <= file_size - offset;
	}

	bool seek_absolute(FILE* file, std::uint64_t offset)
	{
		return offset <= static_cast<std::uint64_t>(std::numeric_limits<long>::max()) &&
			fseek(file, static_cast<long>(offset), SEEK_SET) == 0;
	}

	bool current_offset(FILE* file, std::uint64_t& output)
	{
		const long position = ftell(file);
		if (position < 0) return false;
		output = static_cast<std::uint64_t>(position);
		return true;
	}

	bool read_utf16z_bounded(FILE* file, std::uint64_t extent_end,
		std::string& output)
	{
		std::wstring value;
		while (true) {
			std::uint64_t position = 0;
			if (!current_offset(file, position) || position > extent_end ||
				extent_end - position < sizeof(std::uint16_t)) return false;
			std::uint16_t code_unit = 0;
			if (fread(&code_unit, 1, sizeof(code_unit), file) != sizeof(code_unit)) return false;
			if (code_unit == 0) break;
			value.push_back(static_cast<wchar_t>(code_unit));
		}
		try {
			std::vector<std::uint8_t> utf8;
			utf8::utf16to8(value.begin(), value.end(), std::back_inserter(utf8));
			output.assign(utf8.begin(), utf8.end());
			return true;
		} catch (const utf8::invalid_utf16&) {
			return false;
		}
	}

	bool read_version_header_bounded(vs_version_info_header& header, FILE* file,
		std::uint64_t extent_end)
	{
		constexpr std::uint64_t fixed_size = 3 * sizeof(std::uint16_t);
		std::uint64_t position = 0;
		memset(&header, 0, fixed_size);
		if (!current_offset(file, position) || position > extent_end ||
			extent_end - position < fixed_size ||
			fread(&header, 1, fixed_size, file) != fixed_size) {
			return false;
		}
		if (header.Length == 0 || header.Length < fixed_size ||
			header.Length > extent_end - position) {
			return false;
		}
		const std::uint64_t block_end = position + header.Length;
		if (!read_utf16z_bounded(file, block_end, header.Key) ||
			!current_offset(file, position)) {
			return false;
		}

		const std::uint64_t padding = (4 - position % 4) % 4;
		if (position > block_end || padding > block_end - position) {
			return false;
		}
		return seek_absolute(file, position + padding);
	}

	// Fallback mutex only serializes access within this translation unit.
	std::mutex& io_mutex_or_fallback(const pMutex& mutex) {
		static std::mutex fallback_mutex;
		return mutex ? *mutex : fallback_mutex;
	}

}

PE::resource_directory_result PE::_read_image_resource_directory(image_resource_directory& dir,
	size_t& remaining_entries, std::uint64_t relative_offset) const
{
	if (!_ioh || _file_handle == nullptr) {
		return resource_directory_result::read_error;
	}

	const std::uint64_t root_offset =
		rva_to_offset(_ioh->directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
	if (!root_offset ||
		relative_offset > std::numeric_limits<std::uint64_t>::max() - root_offset) {
		CAPPED_LOGGING_ERROR
		PRINT_ERROR << "Invalid IMAGE_RESOURCE_DIRECTORY relative offset."
			<< DEBUG_INFO_INSIDEPE << std::endl;
		CAPPED_LOGGING_END
		return resource_directory_result::read_error;
	}
	const std::uint64_t target = root_offset + relative_offset;
	if (!fits_file_range(target, IMAGE_RESOURCE_DIRECTORY_SIZE, _file_size) ||
		!seek_absolute(_file_handle.get(), target)) {
		CAPPED_LOGGING_ERROR
		PRINT_ERROR << "Invalid IMAGE_RESOURCE_DIRECTORY bounds."
			<< DEBUG_INFO_INSIDEPE << std::endl;
		CAPPED_LOGGING_END
		return resource_directory_result::read_error;
	}

	unsigned int size = static_cast<unsigned int>(IMAGE_RESOURCE_DIRECTORY_SIZE);
	dir.Entries.clear();
	if (size != fread(&dir, 1, size, _file_handle.get()))
	{
		CAPPED_LOGGING_ERROR
		PRINT_ERROR << "Could not read an IMAGE_RESOURCE_DIRECTORY." << DEBUG_INFO_INSIDEPE << std::endl;
		CAPPED_LOGGING_END
		return resource_directory_result::read_error;
	}

	const size_t entry_count = static_cast<size_t>(dir.NumberOfIdEntries) +
		static_cast<size_t>(dir.NumberOfNamedEntries);
	if (entry_count > MAX_RESOURCE_DIRECTORY_ENTRIES || entry_count > remaining_entries)
	{
		CAPPED_LOGGING_ERROR
		PRINT_ERROR << "The PE's resource section exceeds the parsing limits. Resources will not be parsed."
					<< DEBUG_INFO_INSIDEPE << std::endl;
		CAPPED_LOGGING_END
		return resource_directory_result::limit_exceeded;
	}
	remaining_entries -= entry_count;

	if (dir.Characteristics != 0)
	{
		CAPPED_LOGGING_WARNING
		PRINT_WARNING << "An IMAGE_RESOURCE_DIRECTORY's characteristics should always be 0. The PE may have been manually edited." << DEBUG_INFO_INSIDEPE << std::endl;
		CAPPED_LOGGING_END
	}

	for (size_t i = 0; i < entry_count; ++i)
	{
		auto entry = std::make_shared<image_resource_directory_entry>();
		size = 2*sizeof(std::uint32_t);
		memset(entry.get(), 0, size);
		if (size != fread(entry.get(), 1, size, _file_handle.get()))
		{
			CAPPED_LOGGING_ERROR
			PRINT_ERROR << "Could not read an IMAGE_RESOURCE_DIRECTORY_ENTRY." << DEBUG_INFO_INSIDEPE << std::endl;
			CAPPED_LOGGING_END
			return resource_directory_result::read_error;
		}

		// For named entries, NameOrId is a RVA to a string: retrieve it and NameOrId has high bit set to 1.
		if (entry->NameOrId & 0x80000000)
		{
			const std::uint64_t name_relative_offset = entry->NameOrId & 0x7fffffffu;
			const long next_entry_offset = ftell(_file_handle.get());
			if (next_entry_offset < 0) {
				PRINT_ERROR << "Could not locate the next IMAGE_RESOURCE_DIRECTORY_ENTRY."
					<< DEBUG_INFO_INSIDEPE << std::endl;
				return resource_directory_result::read_error;
			}
			const std::uint64_t saved_offset = static_cast<std::uint64_t>(next_entry_offset);
			bool valid_name = true;
			std::uint64_t name_offset = 0;
			if (name_relative_offset > std::numeric_limits<std::uint64_t>::max() - root_offset)
			{
				CAPPED_LOGGING_ERROR
				PRINT_ERROR << "Invalid IMAGE_RESOURCE_DIRECTORY_ENTRY name offset."
					<< DEBUG_INFO_INSIDEPE << std::endl;
				CAPPED_LOGGING_END
				valid_name = false;
			}
			else {
				name_offset = root_offset + name_relative_offset;
			}
			if (valid_name &&
				(name_offset > std::numeric_limits<unsigned int>::max() ||
				!fits_file_range(name_offset, sizeof(std::uint16_t), _file_size) ||
				!seek_absolute(_file_handle.get(), name_offset))) {
				CAPPED_LOGGING_ERROR
				PRINT_ERROR << "Invalid IMAGE_RESOURCE_DIRECTORY_ENTRY name bounds."
					<< DEBUG_INFO_INSIDEPE << std::endl;
				CAPPED_LOGGING_END
				valid_name = false;
			}

			std::uint16_t name_length = 0;
			if (valid_name &&
				(sizeof(name_length) != fread(&name_length, 1, sizeof(name_length), _file_handle.get()) ||
				!fits_file_range(name_offset, sizeof(name_length) +
					2 * static_cast<std::uint64_t>(name_length), _file_size) ||
				!utils::read_string_at_offset(_file_handle.get(),
					static_cast<unsigned int>(name_offset), entry->NameStr, true))) {
				CAPPED_LOGGING_ERROR
				PRINT_ERROR << "Could not read an IMAGE_RESOURCE_DIRECTORY_ENTRY's name."
					<< DEBUG_INFO_INSIDEPE << std::endl;
				CAPPED_LOGGING_END
				valid_name = false;
			}
			if (!fits_file_range(saved_offset, 0, _file_size) ||
				!seek_absolute(_file_handle.get(), saved_offset)) {
				PRINT_ERROR << "Could not restore the next IMAGE_RESOURCE_DIRECTORY_ENTRY."
					<< DEBUG_INFO_INSIDEPE << std::endl;
				return resource_directory_result::read_error;
			}
			if (!valid_name) {
				continue;
			}
		}

		dir.Entries.push_back(entry);
	}

	return resource_directory_result::success;
}

// ----------------------------------------------------------------------------

bool PE::_parse_resources()
{
	const size_t original_resource_count = _resource_table.size();
	size_t remaining_entries = MAX_RESOURCE_ENTRIES;
	auto abort_resource_parse = [&]() {
		_resource_table.resize(original_resource_count);
		return false;
	};

	if (!_ioh || _file_handle == nullptr) {
		return false;
	}
	if (!_reach_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE, 0,
		"IMAGE_RESOURCE_DIRECTORY"))	{ // No resources.
		return true;
	}

	image_resource_directory root;
	const auto root_result = _read_image_resource_directory(root, remaining_entries);
	if (root_result == resource_directory_result::limit_exceeded) {
		return abort_resource_parse();
	}
	if (root_result == resource_directory_result::read_error) {
		return false;
	}

	// Read Type directories
	for (std::vector<pimage_resource_directory_entry>::iterator it = root.Entries.begin() ; it != root.Entries.end() ; ++it)
	{
		image_resource_directory type;
		const auto type_result = _read_image_resource_directory(
			type, remaining_entries, (*it)->OffsetToData & 0x7FFFFFFF);
		if (type_result == resource_directory_result::limit_exceeded) {
			return abort_resource_parse();
		}
		if (type_result == resource_directory_result::read_error) {
			continue;
		}

		// Read Name directory
		for (std::vector<pimage_resource_directory_entry>::iterator it2 = type.Entries.begin() ; it2 != type.Entries.end() ; ++it2)
		{
			image_resource_directory name;
			const auto name_result = _read_image_resource_directory(
				name, remaining_entries, (*it2)->OffsetToData & 0x7FFFFFFF);
			if (name_result == resource_directory_result::limit_exceeded) {
				return abort_resource_parse();
			}
			if (name_result == resource_directory_result::read_error) {
				continue;
			}

			// Read the IMAGE_RESOURCE_DATA_ENTRY
			for (std::vector<pimage_resource_directory_entry>::iterator it3 = name.Entries.begin() ; it3 != name.Entries.end() ; ++it3)
			{
				image_resource_data_entry entry;
				memset(&entry, 0, sizeof(image_resource_data_entry));

				const std::uint64_t data_entry_rva =
					static_cast<std::uint64_t>(_ioh->directories[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) +
					static_cast<std::uint64_t>((*it3)->OffsetToData & 0x7fffffffu);
				if (data_entry_rva > std::numeric_limits<std::uint32_t>::max())
				{
					CAPPED_LOGGING_ERROR
					PRINT_ERROR << "Invalid IMAGE_RESOURCE_DATA_ENTRY relative RVA."
						<< DEBUG_INFO_INSIDEPE << std::endl;
					CAPPED_LOGGING_END
					continue;
				}
				const std::uint64_t data_entry_offset = rva_to_offset(data_entry_rva);
				if (!data_entry_offset ||
					!fits_file_range(data_entry_offset, IMAGE_RESOURCE_DATA_ENTRY_SIZE, _file_size) ||
					!seek_absolute(_file_handle.get(), data_entry_offset))
				{
					CAPPED_LOGGING_ERROR
					PRINT_ERROR << "Invalid IMAGE_RESOURCE_DATA_ENTRY bounds."
						<< DEBUG_INFO_INSIDEPE << std::endl;
					CAPPED_LOGGING_END
					continue;
				}

				if (sizeof(image_resource_data_entry) != fread(&entry, 1, sizeof(image_resource_data_entry), _file_handle.get()))
				{
					CAPPED_LOGGING_ERROR
					PRINT_ERROR << "Could not read an IMAGE_RESOURCE_DATA_ENTRY." << DEBUG_INFO_INSIDEPE << std::endl;
					CAPPED_LOGGING_END
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

				std::uint64_t payload_offset = rva_to_offset(entry.OffsetToData);
				if (!payload_offset)
				{
					CAPPED_LOGGING_WARNING
					PRINT_WARNING << "Could not locate the section containing resource ";
					if (id) {
						std::cerr << id << DEBUG_INFO_INSIDEPE;
					}
					else {
						std::cerr << r_name << DEBUG_INFO_INSIDEPE;
					}
					std::cerr << ". Trying to use the RVA as an offset..." << DEBUG_INFO_INSIDEPE << std::endl;
					CAPPED_LOGGING_END
					payload_offset = entry.OffsetToData;
				}
				if (payload_offset > std::numeric_limits<std::uint32_t>::max() ||
					!fits_file_range(payload_offset, entry.Size, _file_size)) {
					CAPPED_LOGGING_ERROR
					PRINT_ERROR << "Invalid IMAGE_RESOURCE_DATA_ENTRY payload bounds."
						<< DEBUG_INFO_INSIDEPE << std::endl;
					CAPPED_LOGGING_END
					continue;
				}
				const std::uint32_t offset = static_cast<std::uint32_t>(payload_offset);
				pResource res;
				if (entry.Size == 0)
				{
					CAPPED_LOGGING_WARNING
					if (r_name != "") {
						PRINT_WARNING << "Resource " << r_name << " has a size of 0!" << DEBUG_INFO_INSIDEPE << std::endl;
					}
					else {
						PRINT_WARNING << "Resource " << id << " has a size of 0!" << DEBUG_INFO_INSIDEPE << std::endl;
					}
					CAPPED_LOGGING_END
					continue;
				}

				// Sanity check: verify that no resource is already pointing to the given offset.
				bool is_malformed = false;
				for (auto it4 = _resource_table.begin() ; it4 != _resource_table.end() ; ++it4)
				{
					if (*it4 != nullptr && (*it4)->get_offset() == offset && (*it4)->get_size() == entry.Size)
					{
						// Only print this error message once to avoid flooding stderr.
						static bool warned_once = false;
						if (!warned_once) {
							PRINT_WARNING << "The PE contains duplicate resources. It was almost certainly crafted manually."
										  << DEBUG_INFO_INSIDEPE << std::endl;
							warned_once = true;
						}
						is_malformed = true;
						break;
					}
				}
				if (is_malformed) {  // Duplicate resource. Do not add it again.
					continue;
				}

				if (r_name != "")
				{
					res = std::make_shared<Resource>(r_type,
													   r_name,
													   r_language,
													   entry.Codepage,
													   entry.Size,
													   name.TimeDateStamp,
													   offset,
													   _resource_path,
													   _file_handle,
													   _file_size,
													   _io_mutex);
				}
				else { // No name: call the constructor with the resource ID instead.
					res = std::make_shared<Resource>(r_type,
													   id,
													   r_language,
													   entry.Codepage,
													   entry.Size,
													   name.TimeDateStamp,
													   offset,
													   _resource_path,
													   _file_handle,
													   _file_size,
													   _io_mutex);
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
	auto res = std::make_shared<std::vector<std::uint8_t> >();

	// When file size is unknown (_file_size == 0), resource materialization is disabled.
	if (_file_size == 0)
	{
		PRINT_ERROR << "Cannot load resource " << *get_name()
					<< " because the PE file size is unknown."
					<< DEBUG_INFO << std::endl;
		return res;
	}

	FILE* f = nullptr;
	long saved_offset = -1;
	size_t read_bytes;
	std::unique_lock<std::mutex> lock(io_mutex_or_fallback(_io_mutex));
	if (!_reach_data(f, saved_offset)) {
		return res;
	}

	if (_file_size > 0 &&
		static_cast<std::uint64_t>(_offset_in_file) + static_cast<std::uint64_t>(_size) > _file_size)
	{
		PRINT_ERROR << "Resource " << *get_name() << " is bigger than the PE. Not trying to load it in memory."
					<< DEBUG_INFO << std::endl;
		goto END;
	}

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
	if (f != nullptr && saved_offset != -1) {
		if (fseek(f, saved_offset, SEEK_SET)) {
			res->resize(0);
		}
	}
	return res;
}

// ----------------------------------------------------------------------------

bool parse_version_info_header(vs_version_info_header& header, FILE* f)
{
	memset(&header, 0, 3 * sizeof(std::uint16_t));
	if (3*sizeof(std::uint16_t) != fread(&header, 1, 3*sizeof(std::uint16_t), f))
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
		return std::make_shared<std::string>();
	}
	shared_bytes manifest_bytes = get_raw_data();
	return std::make_shared<std::string>(manifest_bytes->begin(), manifest_bytes->end());
}

// ----------------------------------------------------------------------------

template<>
DECLSPEC const_shared_strings Resource::interpret_as()
{
	auto res = std::make_shared<std::vector<std::string> >();
	if (_type != "RT_STRING")
	{
		PRINT_WARNING << "Resources of type " << _type << " cannot be interpreted as vectors of strings." << DEBUG_INFO << std::endl;
		return res;
	}
	if (_file_size == 0) {
		PRINT_ERROR << "Cannot load resource " << *get_name()
					<< " because the PE file size is unknown."
					<< DEBUG_INFO << std::endl;
		return res;
	}

	FILE* f = nullptr;
	long saved_offset = -1;
	std::unique_lock<std::mutex> lock(io_mutex_or_fallback(_io_mutex));
	if (!_reach_data(f, saved_offset)) {
		goto END;
	}

	// RT_STRING resources are made of 16 contiguous "unicode" strings.
	for (int i = 0; i < 16; ++i)
	{
		res->push_back(utils::read_prefixed_unicode_string(f));
		std::vector<std::uint8_t> utf8result;
	}

	END:
	if (f != nullptr && saved_offset != -1) {
		if (fseek(f, saved_offset, SEEK_SET)) {
			res->clear();
		}
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

	auto res = std::make_shared<bitmap>();
	const size_t header_size = sizeof(bitmap_header);
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
	std::uint32_t dib_header_size = 0;
	std::uint32_t colors_used = 0;
	std::uint16_t bit_count;
	memcpy(&dib_header_size, &(res->data[0]), sizeof(std::uint32_t)); // DIB header size is located at offset 0.
	memcpy(&bit_count, &(res->data[14]), sizeof(std::uint16_t));
	memcpy(&colors_used, &(res->data[32]), sizeof(std::uint32_t));

	if (!((bit_count >= 1 && bit_count <= 8) || bit_count == 24 || bit_count == 32)) {
		return pbitmap();
	}
	if (colors_used == 0 && bit_count <= 8) {
		colors_used = std::uint32_t{1} << bit_count;
	}

	const std::uint64_t pixel_offset = static_cast<std::uint64_t>(header_size) +
		static_cast<std::uint64_t>(dib_header_size) + 4ull * colors_used;
	if (pixel_offset > std::numeric_limits<std::uint32_t>::max()) {
		return pbitmap();
	}
	res->OffsetToData = static_cast<std::uint32_t>(pixel_offset);
	return res;
}

// ----------------------------------------------------------------------------

template<>
DECLSPEC pgroup_icon_directory Resource::interpret_as()
{
	if (_type != "RT_GROUP_ICON" && _type != "RT_GROUP_CURSOR") {
		return pgroup_icon_directory();
	}
	if (_file_size == 0) {
		PRINT_ERROR << "Cannot load resource " << *get_name()
					<< " because the PE file size is unknown."
					<< DEBUG_INFO << std::endl;
		return pgroup_icon_directory();
	}
	FILE* f = nullptr;
	long saved_offset = -1;
	std::unique_lock<std::mutex> lock(io_mutex_or_fallback(_io_mutex));
	if (!_reach_data(f, saved_offset)) {
		return pgroup_icon_directory();
	}

	auto res = std::make_shared<group_icon_directory>();
	unsigned int size = sizeof(std::uint16_t) * 3;
	if (size != fread(res.get(), 1, size, f))
	{
		res.reset();
		goto END;
	}

	for (unsigned int i = 0; i < res->Count; ++i)
	{
		auto entry = std::make_shared<group_icon_directory_entry>();

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
			fread(&(entry->Width), 1, sizeof(std::uint8_t), f);
			fseek(f, 1, SEEK_CUR);
			fread(&(entry->Height), 1, sizeof(std::uint8_t), f);
            entry->Height /= 2; // For some reason, twice the actual height is stored here.
			fseek(f, 1, SEEK_CUR);
			fread(&(entry->Planes), 1, sizeof(std::uint16_t), f);
			fread(&(entry->BitCount), 1, sizeof(std::uint16_t), f);
			fread(&(entry->BytesInRes), 1, sizeof(std::uint32_t), f);
			fread(&(entry->Id), 1, sizeof(std::uint16_t), f);
			if (ferror(f) || feof(f))
			{
				res.reset();
				goto END;
			}
		}

		res->Entries.push_back(entry);
	}

	END:
	if (f != nullptr && saved_offset != -1) {
		if (fseek(f, saved_offset, SEEK_SET)) {
			res.reset();
		}
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
	if (_file_size == 0) {
		PRINT_ERROR << "Cannot load resource " << *get_name()
					<< " because the PE file size is unknown."
					<< DEBUG_INFO << std::endl;
		return pversion_info();
	}

	FILE* f = nullptr;
	long saved_offset = -1;
	std::unique_lock<std::mutex> lock(io_mutex_or_fallback(_io_mutex));
	auto res = std::make_shared<version_info>();
	if (!_reach_data(f, saved_offset)) {
		return pversion_info();
	}
	const std::uint64_t resource_start = _offset_in_file;
	if (!fits_file_range(resource_start, _size, _file_size)) {
		PRINT_ERROR << "Invalid RT_VERSION resource bounds." << DEBUG_INFO << std::endl;
		res.reset();
	}
	else {
		const std::uint64_t resource_end = resource_start + _size;
		auto read_block = [&](vs_version_info_header& header,
			std::uint64_t parent_end, const char* block_name,
			std::uint64_t& block_start, std::uint64_t& block_end) -> bool {
			if (!current_offset(f, block_start) || block_start > parent_end ||
				!read_version_header_bounded(header, f, parent_end)) {
				PRINT_ERROR << "Could not read the RT_VERSION " << block_name
					<< " header within its parent bounds." << DEBUG_INFO << std::endl;
				return false;
			}

			std::uint64_t after_header = 0;
			if (!current_offset(f, after_header) || after_header < block_start) {
				PRINT_ERROR << "Could not determine the RT_VERSION " << block_name
					<< " extent." << DEBUG_INFO << std::endl;
				return false;
			}
			const std::uint64_t consumed = after_header - block_start;
			if (header.Length == 0 || header.Length < consumed) {
				PRINT_ERROR << "The RT_VERSION " << block_name
					<< " has an invalid Length." << DEBUG_INFO << std::endl;
				return false;
			}
			if (header.Length > parent_end - block_start) {
				PRINT_ERROR << "The RT_VERSION " << block_name
					<< " exceeds its parent bounds." << DEBUG_INFO << std::endl;
				return false;
			}
			block_end = block_start + header.Length;
			return true;
		};

		auto seek_next_block = [&](std::uint64_t block_start,
			std::uint64_t declared_length, std::uint64_t block_end,
			std::uint64_t parent_end, const char* block_name) -> bool {
			if (block_end == parent_end) {
				return seek_absolute(f, block_end);
			}
			const std::uint64_t alignment = (4 - declared_length % 4) % 4;
			const std::uint64_t remaining = parent_end - block_end;
			if (remaining <= alignment) {
				return seek_absolute(f, parent_end);
			}
			const std::uint64_t aligned_length = declared_length + alignment;
			const std::uint64_t next_start = block_start + aligned_length;
			if (next_start > parent_end || !seek_absolute(f, next_start)) {
				PRINT_ERROR << "Could not reach the next RT_VERSION " << block_name
					<< " within its parent bounds." << DEBUG_INFO << std::endl;
				return false;
			}
			return true;
		};

		const bool parsed = [&]() -> bool {
			std::uint64_t root_start = 0;
			std::uint64_t root_end = 0;
			if (!read_block(res->Header, resource_end, "root", root_start, root_end)) {
				return false;
			}

			std::uint64_t fixed_info_offset = 0;
			if (!current_offset(f, fixed_info_offset) ||
				!fits_file_range(fixed_info_offset, sizeof(fixed_file_info), root_end)) {
				PRINT_ERROR << "VS_FIXED_FILE_INFO exceeds the RT_VERSION resource."
					<< DEBUG_INFO << std::endl;
				return false;
			}
			res->Value = std::make_shared<fixed_file_info>();
			memset(res->Value.get(), 0, sizeof(fixed_file_info));
			if (fread(res->Value.get(), 1, sizeof(fixed_file_info), f) != sizeof(fixed_file_info) ||
				res->Value->Signature != 0xfeef04bd) {
				PRINT_ERROR << "Could not read the RT_VERSION VS_FIXED_FILE_INFO."
					<< DEBUG_INFO << std::endl;
				return false;
			}

			bool found_string_file_info = false;
			std::uint64_t child_start = 0;
			if (!current_offset(f, child_start) || child_start > root_end) {
				PRINT_ERROR << "Could not determine the RT_VERSION child extent."
					<< DEBUG_INFO << std::endl;
				return false;
			}
			while (child_start < root_end) {
				vs_version_info_header child;
				std::uint64_t child_end = 0;
				if (!read_block(child, root_end, "child", child_start, child_end)) {
					return false;
				}

				if (child.Key == "StringFileInfo") {
					found_string_file_info = true;
					bool found_string_table = false;
					std::uint64_t table_start = 0;
					if (!current_offset(f, table_start) || table_start > child_end) {
						PRINT_ERROR << "Could not determine the RT_VERSION StringTable extent."
							<< DEBUG_INFO << std::endl;
						return false;
					}
					while (table_start < child_end) {
						vs_version_info_header table;
						std::uint64_t table_end = 0;
						if (!read_block(table, child_end, "StringTable",
							table_start, table_end)) {
							return false;
						}
						found_string_table = true;

						unsigned int language = 0;
						std::stringstream ss(table.Key);
						ss >> std::hex >> language;
						if (!ss.fail()) {
							res->Language = *nt::translate_to_flag(
								(language >> 16) & 0xFFFF, nt::LANG_IDS);
						}
						else {
							PRINT_WARNING << "An RT_VERSION language ID could not be translated ("
								<< table.Key << ")!" << std::endl;
							res->Language = "UNKNOWN";
						}

						std::uint64_t string_start = 0;
						if (!current_offset(f, string_start) || string_start > table_end) {
							PRINT_ERROR << "Could not determine the RT_VERSION string extent."
								<< DEBUG_INFO << std::endl;
							return false;
						}
						while (string_start < table_end) {
							vs_version_info_header string;
							std::uint64_t string_end = 0;
							if (!read_block(string, table_end, "string",
								string_start, string_end)) {
								return false;
							}
							if (string.ValueLength != 0) {
								std::string value;
								if (!read_utf16z_bounded(f, string_end, value)) {
									PRINT_ERROR << "Could not read an RT_VERSION string value "
										<< "within its string bounds." << DEBUG_INFO << std::endl;
									return false;
								}
								res->StringTable.push_back(std::make_shared<string_pair>(
									string.Key, value));
							}
							if (!seek_next_block(string_start, string.Length, string_end,
								table_end, "string") || !current_offset(f, string_start)) {
								return false;
							}
						}

						if (!seek_next_block(table_start, table.Length, table_end,
							child_end, "StringTable") || !current_offset(f, table_start)) {
							return false;
						}
					}
					if (!found_string_table) {
						PRINT_ERROR << "The RT_VERSION StringFileInfo contains no StringTable."
							<< DEBUG_INFO << std::endl;
						return false;
					}
				}
				else if (child.Key != "VarFileInfo") {
					PRINT_ERROR << "StringFileInfo or VarFileInfo expected in RT_VERSION, read "
						<< child.Key << " instead." << DEBUG_INFO << std::endl;
					return false;
				}

				if (!seek_next_block(child_start, child.Length, child_end,
					root_end, "child") || !current_offset(f, child_start)) {
					return false;
				}
			}

			if (!found_string_file_info) {
				PRINT_ERROR << "StringFileInfo expected in RT_VERSION."
					<< DEBUG_INFO << std::endl;
				return false;
			}
			return true;
		}();
		if (!parsed) {
			res.reset();
		}
	}

	if (f != nullptr && saved_offset != -1) {
		if (fseek(f, saved_offset, SEEK_SET)) {
			res.reset();
		}
	}
	return res;
}

// ----------------------------------------------------------------------------

template<>
DECLSPEC shared_bytes Resource::interpret_as() {
	return get_raw_data();
}

// ----------------------------------------------------------------------------

bool Resource::_reach_data(FILE*& f, long& saved_offset) const
{
	if (!_pe_file) {
		return false;
	}
	if (static_cast<std::uint64_t>(_offset_in_file) >
		static_cast<std::uint64_t>(std::numeric_limits<long>::max())) {
		return false;
	}

	f = _pe_file.get();
	saved_offset = ftell(f);
	if (saved_offset == -1) {
		return false;
	}

	if (!_offset_in_file || fseek(f, _offset_in_file, SEEK_SET))
	{
		// Offset is invalid
		fseek(f, saved_offset, SEEK_SET);
		return false;
	}

	return true;
}

// ----------------------------------------------------------------------------

mana::shared_bytes reconstruct_icon(pgroup_icon_directory directory, const std::vector<pResource>& resources)
{
	std::vector<std::uint8_t> res;

	if (directory == nullptr) {
		return shared_bytes();
	}

	// Sanity check.
	if (directory->Count > resources.size())
	{
		PRINT_ERROR << "The number of ICON_DIRECTORY_ENTRIES is bigger than the number of resources in the file." << DEBUG_INFO << std::endl;
		return shared_bytes();
	}

	std::uint32_t header_size = 3 * sizeof(std::uint16_t) + directory->Count * sizeof(group_icon_directory_entry);
	try {
		res.resize(header_size);
	}
	catch (const std::bad_alloc)
	{
		PRINT_ERROR << "Could not allocate enough memory to reconstruct an icon. This PE may have been manually modified." << DEBUG_INFO << std::endl;
		return shared_bytes();
	}
	memcpy(&res[0], directory.get(), 3 * sizeof(std::uint16_t));

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
			return shared_bytes();
		}

		shared_bytes icon_bytes = icon->get_raw_data();
		memcpy(&res[3 * sizeof(std::uint16_t) + i * sizeof(group_icon_directory_entry)],
			   directory->Entries[i].get(),
			   sizeof(group_icon_directory_entry) - sizeof(std::uint32_t)); // Don't copy the last field.
		// Fix the icon_directory_entry with the offset in the file instead of a RT_ICON id
		size_t size_fix = res.size();
		memcpy(&res[3 * sizeof(std::uint16_t) + (i+1) * sizeof(group_icon_directory_entry) - sizeof(std::uint32_t)],
			   &size_fix,
			   sizeof(std::uint32_t));
		// Append the icon bytes at the end of the data
		if (directory->Type == 1) { // General case for icons
			auto new_size = static_cast<std::uint32_t>(icon_bytes->size());
			memcpy(&res[3 * sizeof(std::uint16_t) + i * sizeof(group_icon_directory_entry) + 8], &new_size, sizeof(std::uint32_t));
			res.insert(res.end(), icon_bytes->begin(), icon_bytes->end());
		}
		else if (icon_bytes->size() >= 4) // Cursors have a "hotspot" structure that we have to discard to create a valid ico.
        {
			res.insert(res.end(), icon_bytes->begin() + 2 * sizeof(std::uint16_t), icon_bytes->end());
            // Remove 4 from the size to account for this suppression
            auto new_size = static_cast<std::uint32_t>(icon_bytes->size() - 4);
            memcpy(&res[3 * sizeof(std::uint16_t) + i * sizeof(group_icon_directory_entry) + 8], &new_size, sizeof(std::uint32_t));
		}
		else { // Invalid cursor.
			return shared_bytes();
		}
	}

	return std::make_shared<std::vector<std::uint8_t> >(res);
}

// ----------------------------------------------------------------------------

/**
 * @brief   Function which writes bytes to a given file. Created to prevent code
 * duplication between extract and icon_extract.
 *
 * @param   const std::filesystem::path& destination The path to the file to write.
 * @param   std::vector<std::uint8_t> data The data to write.
 *
 * @return  Whether the file creation succeeded.
 */
bool write_data_to_file(const std::filesystem::path& destination, std::vector<std::uint8_t> data)
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

bool Resource::extract(const std::filesystem::path& destination)
{
    shared_bytes data;
	if (_type == "RT_GROUP_ICON" || _type == "RT_GROUP_CURSOR")
    {
        PRINT_WARNING << "Use icon_extract to properly recreate icons." << std::endl;
        data = get_raw_data();
	}
    else if (_type == "RT_BITMAP")
    {
		const size_t header_size = sizeof(bitmap_header);
        auto bmp = interpret_as<pbitmap>();
        if (bmp == nullptr)
        {
            PRINT_ERROR << "Bitmap " << _name << " is malformed!" << std::endl;
            return false;
        }

		auto bmp_bytes = std::make_shared<std::vector<std::uint8_t> >(header_size);
		const bitmap_header& header = *bmp;
		memcpy(bmp_bytes->data(), &header, header_size);
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

bool Resource::icon_extract(const std::filesystem::path& destination,
                            const std::vector<pResource>& resources)
{
    if (_type != "RT_GROUP_ICON" && _type != "RT_GROUP_CURSOR")
    {
        PRINT_WARNING << "Called icon_extract on a non-icon resource!" << std::endl;
        return extract(destination);
    }
    auto data = reconstruct_icon(interpret_as<pgroup_icon_directory>(), resources);
	if (!data || data->empty())
	{
		PRINT_WARNING << "Resource " << _id << " is empty!" << DEBUG_INFO << std::endl;
		return true;
	}

    return write_data_to_file(destination, *data);
}

} // !namespace mana
