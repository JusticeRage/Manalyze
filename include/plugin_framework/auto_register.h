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

#include "plugin_manager.h"
#include "plugin.h"

namespace plugin {

/**
 *	@brief	This class enables easy and automatic registration for
 *			static plugins.
 *
 *	To use it, simply declare a global AutoRegister somewhere in your
 *	plugin code (i.e. AutoRegister<MyPlugin> auto_register;). And that's it.
 *
 *	@param	class T	The class of the plugin to register.
 */
template<class T>
class AutoRegister
{
public:
	AutoRegister()
	{
		pPlugin plugin = pPlugin(new StaticPlugin<T>());
		PluginManager& pm = PluginManager::get_instance();
		pm.register_plugin(plugin);
	}
};

} // !namespace plugin
