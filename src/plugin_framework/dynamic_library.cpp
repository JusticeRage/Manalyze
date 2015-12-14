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

#include "plugin_framework/dynamic_library.h"

namespace plugin {

SharedLibrary::SharedLibrary(void* handle) : _handle(handle) {}

SharedLibrary::~SharedLibrary() {
	unload();
}

pSharedLibrary SharedLibrary::load(const std::string& name)
{
	if (name.empty()) {
		return pSharedLibrary();
	}

	void * handle = nullptr;

	#ifdef BOOST_WINDOWS_API
		handle = ::LoadLibraryA(name.c_str());
		if (handle == nullptr)
		{
			PRINT_ERROR << "Could not open " << name << "." << std::endl;
			return pSharedLibrary();
		}
	#else
		handle = ::dlopen(name.c_str(), RTLD_NOW);
		if (!handle)
		{
			PRINT_ERROR << "Could not open " << name << " (" << ::dlerror() << ")." << std::endl;
			return pSharedLibrary();
		}
	#endif
	return pSharedLibrary(new SharedLibrary(handle));
}

void SharedLibrary::unload()
{
	if (_handle == nullptr) {
		return;
	}
	#ifdef BOOST_WINDOWS_API
		::FreeLibrary((HMODULE) _handle);
	#else
		::dlclose(_handle);
	#endif
	_handle = nullptr;
}

void* SharedLibrary::resolve_symbol(const std::string& symbol) const
{
	if (!_handle)
		return nullptr;

	#ifdef BOOST_WINDOWS_API
		return ::GetProcAddress((HMODULE) _handle, symbol.c_str());
	#else
		return ::dlsym(_handle, symbol.c_str());
	#endif
}

} // !namespace plugin
