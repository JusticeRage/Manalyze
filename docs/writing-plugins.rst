***************
Writing plugins
***************

In this section, we'll learn how to write plugins for this project.

Internal and external plugins
=============================

There are two ways plugins can be integrated in Manalyze. You can either:

* Statically bundle them within the executable of the application (internal plugins).
* Build them as a separate library which will be loaded dynamically (external plugins).

Which one should you choose? Here are some guidelines to help you decide:

- If you intend to distribute your plugin, you should write an external plugin. It makes more sense to share a ``.so`` or ``.dll`` file than a whole new Manalyze binary with added code. 
- If your plugin is relatively small and isn't meant to be shared, it is okay to write an internal plugin. Conversely, complex plugins which pull third-party libraries should be compiled in their own module.

In any case, aside from small discreapancies in the way each type of plugin is built, the code you will write will be virtually the same.

A sample plugin
===============

Let's dive right into it and write an Hello World plugin! Let's create ``plugins/plugin_helloworld.cpp``.

Internal plugin skeleton:
-------------------------

::

	#include "plugin_framework/plugin_interface.h"
	#include "plugin_framework/auto_register.h"

	namespace plugin
	{

	class HelloWorldPlugin : public IPlugin
	{

	};

	AutoRegister<HelloWorldPlugin> auto_register_helloworld;

	} //!namespace plugin

Modifications to ``CMakeLists.txt``: add a reference to this new source file with the other internal plugins, on the third line of the following snippet::

    add_executable(manalyze src/main.cpp src/config_parser.cpp src/output_formatter.cpp src/dump.cpp
    		   src/plugin_framework/dynamic_library.cpp src/plugin_framework/plugin_manager.cpp # Plugin system
    		   plugins/plugins_yara.cpp plugins/plugin_packer_detection.cpp plugins/plugin_imports.cpp plugins/plugin_resources.cpp plugins/plugin_helloworld.cpp) # Bundled plugins

External plugin skeleton:
-------------------------

::

	#include "plugin_framework/plugin_interface.h"

	namespace plugin
	{

	class HelloWorldPlugin : public IPlugin
	{

	};

	// ----------------------------------------------------------------------------

	extern "C"
	{
		PLUGIN_API IPlugin* create() { return new HelloWorldPlugin(); }
		PLUGIN_API void destroy(IPlugin* p) { if (p) delete p; }
	};

	} //!namespace plugin

Modifications to ``CMakeLists.txt``: declare a new library, for instance just under the VirusTotal plugin::

    # HelloWorld plugin
    add_library(plugin_helloworld SHARED plugins/plugin_helloworld.cpp)
    target_link_libraries(plugin_helloworld manape hash-library manacommons)

There are some parts missing, but it's okay for now. Points of interest are the mandatory included file(s), and the definition of a new class inheriting from ``plugin::IPlugin`` which defines the interface all plugins must adhere to. Internal plugins contain some additional magic to let the core know about them at startup. If you're building an external plugin, omit the ``AutoRegister`` instance: Manalyze will find it by scanning its folder for library files. Instead, you have to define the ``create`` and ``destroy`` functions so the core can load and unload your plugin.

If you try to build the plugin right now, you'll see that the compiler is very annoyed about some missing functions. Let's go back to our source file and finish our plugin's implementation::

	class HelloWorldPlugin : public IPlugin
	{
		int get_api_version() const override { return 1; }

		pString get_id() const override {
			return boost::make_shared<std::string>("helloworld");
		}

		pString get_description() const override {
			return boost::make_shared<std::string>("A sample plugin.");
		}

		pResult analyze(const mana::PE& pe) override {
			pResult res = create_result();
			res->add_information("Hello world from the plugin!");
			return res;
		}
	};

These functions serve the following purpose:

* ``get_api_version``: the version of the API used by this plugin, in case it evolves and breaks retro-compatibility in the future. Just return 1 for now.
* ``get_id``: the name of the plugin. This is how it will be refered to in the program's help and on the command-line; make sure to pick something unique!
* ``get_description``: a short explanation of what the plugin does. It is only printed when the user calls Manalyze with the ``--help`` option.
* ``analyze``: performs the analysis of the program. We'll get back to this one very soon, for now, it just creates a result object containing a message.

Build the project again, and the plugin will automatically appear in the program's help::

	$ bin/manalyze --help
	Usage:
	  -h [ --help ]         Displays this message.
	  [...]

	Available plugins:
	  [...]
	  - helloworld: A sample plugin.
	  - all: Run all the available plugins.

	$ bin/manalyze -p helloworld malware.mal 
	* Manalyze 1.0 *

	-------------------------------------------------------------------------------
	malware.mal
	-------------------------------------------------------------------------------

	Summary:
	--------
	Architecture:       IMAGE_FILE_MACHINE_I386
	Subsystem:          IMAGE_SUBSYSTEM_WINDOWS_GUI
	Compilation Date:   2015-Apr-23 16:45:58
	Detected languages: English - United States

		Hello world from the plugin!

Great, our code has been called! Now let's try doing something useful.

Plugin results
==============

After performing whatever work they do, plugins send back analysis data to the program's core through ``plugin::Result`` objects. These objects are composed of three things:

* A threat level, which indicates how dangerous the target file is according to the plugin. 
  Keep in mind that plugins are only expected to give an opinion limited to their scope. In other words, it's okay for some plugins to mark known malware as safe: for example, the authenticode plugin would return this threat level for a malware with a valid digital signature. It's the user's job to take all the plugin results into account and determine whether the file is malicious or not.
* A summary describing the plugin's general findings on the PE, or introducing the information which follows.
* Pieces of textual information providing more detailed insight on the target file.

.. TIP:: For instance, the ``imports`` plugin may return a result containing the following data:

	::

		Threat Level: MALICIOUS
		Summary: The PE contains functions mostly used by malwares.
		Information: Uses functions commonly found in keyloggers
		             Has Internet access capabilities
		             Uses Microsoft's cryptographic API

Manalyze takes care of displaying this information to the user when all the plugins have run, and you shouldn't worry about it unless you want to extend the application so it supports a new output format.

Here is how to insert data inside your ``Result``:

Threat level
------------

``set_level`` and ``raise_level`` modify a result's threat level. The only difference between the two is that ``set_level`` will always overwrite the previous value, while ``raise_level`` will only store it if the previous one was "lower". The following threat levels are available:

* ``SAFE``: the plugin has good reason to believe that the input file is not hostile.
* ``NO_OPINION``: the plugin cannot decide whether the input file is malicious or not. Use this threat level if you have gathered information worth mentioning, but which doesn't imply that a program could be malware. For instance, using cryptography is something the user probably wants to know, but containing MD5 constants does not make a program malware.
* ``SUSPICIOUS``: use this one if the input file has characteristics that most legitimate programs don't have (i.e. not all packed applications are malware, but it's certainly a sign).
* ``MALICIOUS``: this threat level should be used when the plugin thinks that the PE file is malware with a high degree of certainty, like when a ClamAV signature matches it.

By default, if no threat level is specified, a value of ``NO_OPINION`` will be assumed.

Sample usage::

	pResult res = create_result();
	// do some tests
	if (bad_things) {
	    res->set_level(MALICIOUS);
	}
	// do more tests
	if (other_things) {
	    res->raise_level(SUSPICIOUS); // Threat level will not decrease if it was MALICIOUS before.
	}
	// do even more tests
	if (actually_ok) {
	    res->set_level(SAFE); // If reached, threat level will be set to SAFE regardless of the previous value.
	}

Summary
-------

Use the ``set_summary`` method to edit the result's summary. There can only be one, so any subsequent calls will overwrite the previous value. Note that the summary is optional and you don't have to set a value if you don't feel the need to.

Sample usage::

	pResult res = create_result();
	res->set_summary("The PE is possibly packed.");

Information
-----------

Information can (and must) be added to the result through the ``add_information`` method. If a result contains no information, Manalyze will assume that it has nothing to report and no output will be generated (even if a threat level or a summary has been set). You may add as many pieces of data as you like, but there is no way to remove one that was already inserted. Finally, the order in which the information is pushed will be preserved.

The ``add_information`` function, or rather set of functions, allow plugin writers to create complex data structures. Let's look at some examples::

	pResult res = create_result();
	res->add_information("Some textual information added to the result.");

	res->add_information("key", "value");

	std::vector<std::string> data;
	data.push_back("One");
	data.push_back("Two");
	data.push_back("Three");
	res->add_information("A list of strings", data);

This code generates the following output when using the JSON formatter::

	"Plugins": {
		"helloworld": {
			"level": 1,
			"plugin_output": {
				"info_0": "Some textual information added to the result.",
				"key": "value"
				"A list of strings": [
					"One",
					"Two",
					"Three"
				]
			}
		}
	}

Internally, all the result data is stored as key-value pairs; if you don't provide a key, Manalyze will generate one automatically which will be omitted whenever possible. Here is the same result presented by the default formatter (when printing human-readable results) ::

    Some textual information added to the result.
    key: value
    A list of strings: One
                       Two
                       Three

PE objects
==========

Now that we know how to create results, we will look more closely at the ``analyze`` method. Here is how it's declared::

	pResult analyze(const mana::PE& pe);

It's return type has been covered already, but what about the argument? This ``PE`` object is all the plugin has to work with, but it contains a lot of information about the input file.
