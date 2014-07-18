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

#ifndef _PLUGIN_INTERFACE_H_
#define _PLUGIN_INTERFACE_H_

#include <string>
#include <boost/shared_ptr.hpp>
#include <boost/system/api_config.hpp>

#include "pe.h"
#include "plugin_framework/result.h"

#ifdef BOOST_WINDOWS_API
#	define PLUGIN_API __declspec(dllexport)
#else
#	define PLUGIN_API __attribute__((visibility("default")))
#endif

namespace plugin {

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
	virtual pResult analyze(const sg::PE& pe) = 0;

	/**
	 *	@brief	Returns the API version for which this plugin was compiled.
	 *
	 *	If this value doesn't match PluginManager::API_VERSION, the plugin will not be loaded.
	 *
	 *	@return	The API version of the plugin.
	 */
	virtual int get_api_version() = 0;

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
};

typedef boost::shared_ptr<IPlugin> pIPlugin;

} // !namespace plugin

#endif // !_PLUGIN_INTERFACE_H_