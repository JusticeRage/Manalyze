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

#ifndef _PLUGIN_MANAGER_H_
#define _PLUGIN_MANAGER_H_

#include <vector>
#include <iostream>
#include <boost/shared_ptr.hpp>
#include <boost/bind.hpp>
#include <boost/optional.hpp>

#include "plugin/dynamic_library.h"
#include "plugin/plugin_interface.h"
#include "plugin/plugin.h"

#include "color.h"

namespace plugin {

/**
 *	@brief	Represents an entry (a "registered plugin") in the plugin register.
 *
 *	Simply contains a reference to the plugin object, and an optional pointer to the shared
 *	library in the case of dynamic plugins.
 */
class RegisterEntry
{
public:
	RegisterEntry(pPlugin p) : _plugin(p), _shared_library() {}
	RegisterEntry(pPlugin p, pSharedLibrary s) : _plugin(p), _shared_library(s) {}

	/**
	 *	@brief	Accesses the associated plugin.
	 */
	pPlugin get_plugin() const { return _plugin; }

	/**
	 *	@brief	Accesses the associated shared library, if it exists.
	 */
	pSharedLibrary get_shared_library() const 
	{ 
		if (_shared_library) {
			return *_shared_library;
		}
		else {
			return pSharedLibrary();
		}
	}

private:
	pPlugin _plugin;
	boost::optional<pSharedLibrary>	_shared_library;
};
typedef boost::shared_ptr<RegisterEntry> pRegisterEntry;

/**
 *	@brief	This class takes care of the management of the plugins.
 *			The task entails loading them and registering them.
 *
 *	This abstraction allows the application to access and use plugins 
 *	while hiding implementation details, such as the distinction
 *	between dynamic and static plugins.
 *
 *	This class implements the singleton design pattern.
 */
class PluginManager
{

public:
	static int API_VERSION;
	typedef std::vector<pRegisterEntry> PluginRegister;

	/**
	 *	@brief	The PluginManager is a singleton. This method returns the
	 *			instance of this class.
	 *
	 */
	static PluginManager& get_instance() 
	{
		static PluginManager pm;
		return pm;
	}

	/**
	 *	@brief	Loads a dynamic plugin.
	 *
	 *	@param	const std::string& path The path to the shared library.
	 */
	void load(const std::string& path);

	/**
	 *	@brief	Registers a plugin.
	 *
	 *	Calling this function only makes sens in the context of a static
	 *	plugin initialization.
	 *
	 *	You should probably not be calling this function directly. Let the
	 *	AutoRegistration class perform this task for you.
	 */
	void register_plugin(pPlugin p) {
		_plugins.push_back(pRegisterEntry(new RegisterEntry(p)));
	}

	/**
	 *	@brief	Returns a vector containing one of each registered plugins.
	 *
	 *	This function goes through the list of registered plugins ("register")
	 *	and instantiates one of each plugin types for the function caller.
	 *
	 *	@return	A vector of plugins.
	 */
	std::vector<pIPlugin> get_plugins() 
	{
		std::vector<pIPlugin> res;
		for (PluginRegister::iterator it = _plugins.begin() ; it != _plugins.end() ; ++it)
		{
			pIPlugin p = (*it)->get_plugin()->instantiate_plugin();
			res.push_back(p);
		}
		return res;
	}

	virtual ~PluginManager() {}

private:
	PluginManager() {}
	PluginManager(const PluginManager&);
	PluginManager& operator=(PluginManager const&);

	PluginRegister _plugins;

};

} // !namespace plugin

#endif // !_PLUGIN_MANAGER_H_