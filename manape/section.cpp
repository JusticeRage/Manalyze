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

#include "manape/section.h"

namespace mana
{

Section::Section(const image_section_header& header,
				 const std::string& path,
				 const std::vector<pString>& coff_string_table)
	  : _virtual_size(header.VirtualSize),
		_virtual_address(header.VirtualAddress),
		_size_of_raw_data(header.SizeOfRawData),
		_pointer_to_raw_data(header.PointerToRawData),
		_pointer_to_relocations(header.PointerToRelocations),
		_pointer_to_line_numbers(header.PointerToLineNumbers),
		_number_of_relocations(header.NumberOfRelocations),
		_number_of_line_numbers(header.NumberOfLineNumbers),
		_characteristics(header.Characteristics),
		_path(path)
{
	_name = std::string((char*) header.Name);

	if (_name.size() > 0 && _name[0] == '/')
	{
		std::stringstream ss;
		unsigned int index;
		ss << header.Name + 1; // Skip the trailing "/"
		ss >> index;

		if (index >= coff_string_table.size()) {
			PRINT_WARNING << "Tried to read outside the COFF string table to get the name of section " << _name << "!" << std::endl;
		}
		else {
			_name = *coff_string_table[index];
		}
	}
}

// ----------------------------------------------------------------------------

shared_bytes Section::get_raw_data() const
{
	auto res = boost::make_shared<std::vector<boost::uint8_t> >();
	if (_size_of_raw_data == 0)
	{
		PRINT_WARNING << "Section " << _name << " has a size of 0!" << DEBUG_INFO << std::endl;
		return res;
	}
	FILE* f = fopen(_path.c_str(), "rb");
	if (f == nullptr) {
		return res;
	}
	if (fseek(f, _pointer_to_raw_data, SEEK_SET))
	{
		fclose(f);
		return res;
	}

	try {
		res->resize(_size_of_raw_data);
	}
	catch (const std::exception& e)
	{
		PRINT_ERROR << "Failed to allocate enough space for section " << *get_name() << "! (" << e.what() << ")"
			<< DEBUG_INFO << std::endl;
		res->resize(0);
		fclose(f);
		return res;
	}

	if (_size_of_raw_data != fread(&(*res)[0], 1, _size_of_raw_data, f))
	{
		PRINT_WARNING << "Raw bytes from section " << _name << " could not be obtained." << std::endl;
		res->resize(0);
	}

	fclose(f);
	return res;
}

// ----------------------------------------------------------------------------

bool is_address_in_section(boost::uint64_t rva, mana::pSection section, bool check_raw_size)
{
	if (!check_raw_size) {
		return section->get_virtual_address() <= rva && rva < section->get_virtual_address() + section->get_virtual_size();
	}
	else {
		return section->get_virtual_address() <= rva && rva < section->get_virtual_address() + section->get_size_of_raw_data();
	}
}

// ----------------------------------------------------------------------------

mana::pSection find_section(unsigned int rva, const std::vector<mana::pSection>& section_list)
{
	mana::pSection res = mana::pSection();
	for (auto it = section_list.begin() ; it != section_list.end() ; ++it)
	{
		if (is_address_in_section(rva, *it))
		{
			res = *it;
			break;
		}
	}

	if (!res) // VirtualSize may be erroneous. Check with RawSizeofData.
	{
		for (auto it = section_list.begin() ; it != section_list.end() ; ++it)
		{
			if (is_address_in_section(rva, *it, true))
			{
				res = *it;
				break;
			}
		}
	}

	return res;
}

} // !namespace mana
