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

#include "plugin_framework/plugin_manager.h"

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
		// Display an error message if the library is likely to be a malformed plugin.
		std::string libname = boost::filesystem::basename(path);
		if (libname.find("libplugin_") == 0 || libname.find("plugin_") == 0) {
			PRINT_ERROR << "Could not resolve " << path << "'s creator or destroyer function!" << std::endl;
		}
		return;
	}
	pPlugin plugin = pPlugin(new DynamicPlugin(c, d));

	// Check the api version for dynamic plugins. Over time, the API may evolve and old plugins could
	// become incompatible.
	pIPlugin test = plugin->instantiate_plugin();
	if (test->get_api_version() != API_VERSION)
	{
		PRINT_ERROR << "The plugin " << *test->get_id() << " is not compatible with this version of the API (expected: "
			<< API_VERSION << ", found: " << test->get_api_version() << ")!" << std::endl;
		return;
	}

	// Verify that the plugin isn't already loaded (no two plugins can have the same name)
	std::vector<pIPlugin> loaded_plugins = get_plugins();
	for (std::vector<pIPlugin>::iterator it = loaded_plugins.begin() ; it != loaded_plugins.end() ; ++it)
	{
		if (*(*it)->get_id() == *test->get_id())
		{
			PRINT_WARNING << "The plugin " << *test->get_id() << " tried to load twice!" << std::endl;
			return;
		}
	}

	// Everything ok: add register the plugin.
	_plugins.push_back(pRegisterEntry(new RegisterEntry(plugin, lib)));
}

// ----------------------------------------------------------------------------

void PluginManager::load_all(const std::string& path)
{
	#ifdef BOOST_WINDOWS_API
		std::string ext(".dll");
	#elif defined BOOST_POSIX_API
		std::string ext(".so");
	#endif

	if (!bfs::exists(path)) {
		return;
	}

	bfs::directory_iterator end_it;
	for (bfs::directory_iterator it(path) ; it != end_it ; ++it)
	{
		if (it->path().extension() == ext) {
			load(it->path().string());
		}
	}
}

// ----------------------------------------------------------------------------

void PluginManager::unload_all() {
	_plugins.clear();
}

// ----------------------------------------------------------------------------

bool name_matches(const std::string& s, pIPlugin p) {
	return *p == s;
}

} // !namespace plugin
