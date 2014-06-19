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

#include "section.h"

namespace sg 
{

Section::Section(const image_section_header& header, const std::string& path)	
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
	// TODO: If the name starts with a slash, then it is followed by an index into the StringTable
	// which is the actual section name. Does it ever happen, though?
}

// ----------------------------------------------------------------------------

std::vector<boost::uint8_t> Section::get_raw_data()
{
	std::vector<boost::uint8_t> res;
	if (_size_of_raw_data == 0)
	{
		PRINT_WARNING << "Section " << _name << " has a size of 0!";
		return res;
	}
	FILE* f = fopen(_path.c_str(), "rb");
	if (f == NULL || fseek(f, _pointer_to_raw_data, SEEK_SET)) 
	{
		fclose(f);
		return res;
	}

	res.resize(_size_of_raw_data);

	if (_size_of_raw_data != fread(&res[0], 1, _size_of_raw_data, f)) 
	{
		PRINT_WARNING << "Raw bytes from section " << _name << " could not be obtained." << std::endl;
		res.resize(0);
	}

	fclose(f);
	return res;
}

}