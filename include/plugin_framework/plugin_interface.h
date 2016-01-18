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
#include <map>
#include <boost/make_shared.hpp>
#include <boost/system/api_config.hpp>

#include "manape/pe.h"
#include "plugin_framework/result.h"

#ifdef BOOST_WINDOWS_API
#	define PLUGIN_API __declspec(dllexport)
#else
#	define PLUGIN_API __attribute__((visibility("default")))
#endif

namespace plugin {

typedef std::map<std::string, std::string> string_map;
typedef boost::shared_ptr<const std::map<std::string, std::string> > shared_string_map;

class IPlugin
{
public:
	virtual ~IPlugin() {}
	bool operator==(const std::string& s) const { return s == *get_id(); }

	/**
	 *	@brief	Performs the analysis of the PE.
	 *
	 *	@param	const sg::PE& pe The PE object to analyze.
	 *
	 *	@return	A shared pointer to a result object, representing the information obtained
	 *			by the plugin.
	 */
	virtual pResult analyze(const mana::PE& pe) = 0;

	/**
	 *	@brief	Returns the API version for which this plugin was compiled.
	 *
	 *	If this value doesn't match PluginManager::API_VERSION, the plugin will not be loaded.
	 *
	 *	@return	The API version of the plugin.
	 */
	virtual int get_api_version() const = 0;

	/**
	 *	@brief	Returns the identifier of the plugin.
	 *
	 *	@return	The ID of the plugin, as a shared pointer since it may
	 *			cross shared object boundaries.
	 */
	virtual boost::shared_ptr<std::string> get_id() const = 0;

	/**
	 *	@brief	Returns the description of the plugin.
	 *
	 *	@return	The description of the plugin, as a shared pointer since it may
	 *			cross shared object boundaries.
	 */
	virtual boost::shared_ptr<std::string> get_description() const = 0;

	void set_config(const string_map& config) {
		_config = boost::make_shared<string_map>(config);
	}

	/**
	 *	@brief	Creates a result object which can be used by a plugin.
	 *
	 *	Result's constructor has been made private because it needs to receive the plugin's name
	 *	in order to fill its internal OutputTreeNode. This function hides the fact that the plugin
	 *	name is forwarded.
	 */
	pResult create_result() const
	{
		pResult res(new Result(*get_id()));
		return res;
	}

protected:
	shared_string_map _config;
};

typedef boost::shared_ptr<IPlugin> pIPlugin;

} // !namespace plugin
