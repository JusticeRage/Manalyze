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

#include "plugin/plugin_manager.h"

namespace plugin {

int PluginManager::API_VERSION = 1;

void PluginManager::load(const std::string& path)
{
	pSharedLibrary lib = SharedLibrary::load(path);
	if (lib == NULL) {
		return;
	}

	DynamicPlugin::creator c = (DynamicPlugin::creator) lib->resolve_symbol("create");
	DynamicPlugin::destroyer d = (DynamicPlugin::destroyer) lib->resolve_symbol("destroy");
	if (!c || !d)
	{
		PRINT_ERROR << "Could not resolve " << path << "'s creator or destroyer function!" << std::endl;
		return;
	}
	pPlugin plugin = pPlugin(new DynamicPlugin(c, d));

	// Check the api version for dynamic plugins. Over time, the API may evolve and old plugins could
	// become incompatible.
	pIPlugin test = plugin->instantiate_plugin();
	if (test->get_api_version() != API_VERSION) 
	{
		PRINT_ERROR << "the plugin " << test->get_id() << " is not compatible with this version of the API (expected: " 
			<< API_VERSION << ", found: " << test->get_api_version() << ")!" << std::endl;
		return;
	}
	
	// Verify that the plugin isn't already loaded (no two plugins can have the same name)
	std::vector<pIPlugin> loaded_plugins = get_plugins();
	for (std::vector<pIPlugin>::iterator it = loaded_plugins.begin() ; it != loaded_plugins.end() ; ++it)
	{
		if ((*it)->get_id() == test->get_id())
		{
			PRINT_WARNING << "The plugin " << test->get_id() << " was loaded twice!" << std::endl;
			return;
		}
	}

	// Everything ok: add register the plugin.
	_plugins.push_back(pRegisterEntry(new RegisterEntry(plugin, lib)));
}

} // !namespace plugin