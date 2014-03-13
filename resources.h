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

#ifndef _RESOURCES_H_
#define _RESOURCES_H_

#include <string>
#include <vector>

#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/shared_array.hpp>

namespace sg
{

class Resource
{
public:
	Resource(const std::string&		type,
			 const std::string&		name,
			 const std::string&		language,
			 boost::uint32_t		codepage,
			 boost::uint32_t		size,
			 unsigned int			offset_in_file,
			 const std::string&		path_to_pe)
		: _type(type), 
		  _name(name), 
		  _language(language), 
		  _codepage(codepage), 
		  _offset_in_file(offset_in_file), 
		  _size(size),
		  _path_to_pe(path_to_pe)
	{}

	virtual ~Resource() {}

	std::string		get_type()		const { return _type; }
	std::string		get_name()		const { return _name; }
	std::string		get_language()	const { return _language; }
	boost::uint32_t	get_codepage()	const { return _codepage; }
	boost::uint32_t	get_size()		const { return _size; }

	/**
	 *	@brief	Retrieves the raw bytes of the resource.
	 *
	 *	@return	A vector containing the read bytes. Its size may be 0 if
	 *			the resource could not be read.
	 */
	std::vector<boost::uint8_t> get_raw_data();
	
	/**
	 *	@brief	Interprets the resource as a given type.
	 *
	 *	All the work is performed in one of the template specializations.
	 *	Currently, the following interpretations are implemented:
	 *	* std::string for RT_MANIFEST
	 *	* std::vector<std::string> for RT_STRING
	 *
	 *	@tparam	T The type into which the resource should be interpreted.
	 *
	 *	@return	An instance of T representing the resource.
	 */
	template <class T>
	T interpret_as();

private:
	std::string		_type;
	std::string		_name;
	std::string		_language;
	boost::uint32_t	_codepage;
	boost::uint32_t	_size;

	// These fields do not describe the PE structure.
	unsigned int	_offset_in_file;
	std::string		_path_to_pe;

	/**
	 *	@brief	Opens the PE file and sets the cursor to the resource bytes.
	 *
	 *	@return	A file object with its cursor correctly set, or NULL if there was an error.
	 */
	FILE* _reach_data();
};
typedef boost::shared_ptr<Resource> pResource;


} // !namespace sg

#endif // !_RESOURCES_H_