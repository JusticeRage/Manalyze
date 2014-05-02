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

#ifndef _SECTION_H_
#define _SECTION_H_

#include <stdio.h>
#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>
#include <vector>

#include "pe_structs.h"
#include "color.h"

namespace sg {

class Section
{

public:
	Section(const image_section_header& header, const std::string& path);

	/**
	 *	@brief	Returns the raw bytes of the section.
	 *
	 *	Note that calling this function for PEs which have giant sections may end up 
	 *	eating a lot of memory.
	 *
	 *	@return	A vector containing the raw bytes of the section. If an error occurs, the vector
	 *			will be empty.
	 */
	std::vector<boost::uint8_t> get_raw_data();

	std::string		get_name()						const { return _name; }
	boost::uint32_t get_virtual_size()				const { return _virtual_size; }
	boost::uint32_t get_virtual_address()			const { return _virtual_address; }
	boost::uint32_t get_size_or_raw_data()			const { return _size_of_raw_data; }
	boost::uint32_t get_pointer_to_raw_data()		const { return _pointer_to_raw_data; }
	boost::uint32_t get_pointer_to_relocations()	const { return _pointer_to_relocations; }
	boost::uint32_t get_pointer_to_line_numbers()	const { return _pointer_to_line_numbers; }
	boost::uint32_t get_number_of_relocations()		const { return _number_of_relocations; }
	boost::uint32_t get_number_of_line_numbers()	const { return _number_of_line_numbers; }
	boost::uint32_t get_characteristics()			const { return _characteristics; }

private:

	// Fields that match the PE structure
	std::string		_name;
	boost::uint32_t _virtual_size;
	boost::uint32_t _virtual_address;
	boost::uint32_t _size_of_raw_data;
	boost::uint32_t _pointer_to_raw_data;
	boost::uint32_t _pointer_to_relocations;
	boost::uint32_t _pointer_to_line_numbers;
	boost::uint16_t _number_of_relocations;
	boost::uint16_t _number_of_line_numbers;
	boost::uint32_t _characteristics;

	// Path to the executable file and location inside it:
	std::string		_path;
	boost::uint32_t	_offset;
};

typedef boost::shared_ptr<Section> pSection;

} // !namespace sg

#endif // !_SECTION_H_