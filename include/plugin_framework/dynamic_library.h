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

#pragma once

#include <string>
#include <sstream>
#include <iostream>

#include <boost/make_shared.hpp>
#include <boost/system/api_config.hpp>

#include "manacommons/color.h"

#ifdef BOOST_WINDOWS_API
	#include <Windows.h>
#else
	#include <dlfcn.h>
#endif

namespace plugin {

/**
 *	@brief	A somewhat multi-platform class which represents a shared object.
 */
class SharedLibrary
{
public:
	/**
	 *	@brief	Loads a shared library.
	 *
	 *	SharedLibrary objects can only be instantiated through this function.
	 *
	 *	@param	const std::string& path The path to the shared object file to load.
	 *
	 *	@return	A pointer to a SharedLibrary representing the loaded file. May be NULL
	 *			if for some reason, the library could not be loaded.
	 */
	static boost::shared_ptr<SharedLibrary> load(const std::string& path);

	~SharedLibrary();

	/**
	 *	@brief	Resolves a symbol in the shared library.
	 *
	 *	@param	const std::string& name The name of the symbol to resolve.
	 *
	 *	@return	The address of the symbol in the module. May be NULL.
	 */
	void* resolve_symbol(const std::string& name) const;

	/**
	 *	@brief	Cleanly unloads the shared library.
	 */
	void unload();

private:
	SharedLibrary();
	SharedLibrary(void* handle);
	SharedLibrary(const SharedLibrary&);

private:
	void* _handle;
};

typedef boost::shared_ptr<SharedLibrary> pSharedLibrary;

} //!namespace plugin
