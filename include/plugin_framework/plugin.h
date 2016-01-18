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

#include "plugin_interface.h"

namespace plugin {

/**
 *	@brief	The generic plugin interface.
 *
 *	All that's required of a Plugin is that it can instantiate
 *	objects which implement the IPlugin interface.
 */
class Plugin
{
public:
	Plugin() {}
	virtual ~Plugin() {}

	/**
	 *	@brief	Creates an instance of the underlying plugin implementation.
	 *
	 *	@return	An instance of the plugin represented by this object.
	 */
	virtual pIPlugin instantiate_plugin() = 0;
};
typedef boost::shared_ptr<Plugin> pPlugin;

/**
 *	@brief	This class represent a plugin which was loaded from a shared library.
 *
 *	Because of the static linking, the destruction of the plugin object has to
 *	be taken care of very meticulously, in order to avoid freeing memory that
 *	was allocated by another CRT.
 *
 *	For this reason, both a creator and a destructor have to be exported by the
 *	shared object.
 */
class DynamicPlugin : public Plugin
{
public:
	typedef IPlugin* (*creator)();
	typedef void (*destroyer)(IPlugin*);

	DynamicPlugin(creator c, destroyer d)
		: _creator(c), _destroyer(d)
	{}

	virtual ~DynamicPlugin() {}

	virtual pIPlugin instantiate_plugin() override
	{
		if (!_destroyer) {
			return pIPlugin(_creator());
		}
		else {
			return pIPlugin(_creator(), _destroyer); // Use the destroyer provided by the library
		}
	}

private:
	creator		_creator;
	destroyer	_destroyer;
};

/**
 *	@brief	Represents a static plugin, i.e. a plugin that was
 *			bundled with the application.
 */
template<class T>
class StaticPlugin : public Plugin
{
public:
	StaticPlugin() {}
	virtual ~StaticPlugin() {}
	virtual pIPlugin instantiate_plugin() override { return pIPlugin(new T()); }
};

} // !namespace plugin
