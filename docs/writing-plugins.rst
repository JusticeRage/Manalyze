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

In any case, aside from small discreapancies in the way each type of plugin is built, the code you will write will be mostly identical.

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
        PLUGIN_API void destroy(IPlugin* p) { delete p; }
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

        pResult analyze(const mana::PE& pe) override
        {
            pResult res = create_result();
            res->add_information("Hello world from the plugin!");
            return res;
        }
    };

These functions serve the following purpose:

* ``get_api_version``: the version of the API used by this plugin, in case it evolves and breaks retro-compatibility in the future. Just return 1 for now.
* ``get_id``: the name of the plugin. This is how it will be referred to in the program's help and on the command-line; make sure to pick something unique!
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

..  _pe_objects:

PE objects
==========

Now that we know how to create results, we will look more closely at the ``analyze`` method. This is where you should write all your plugin's logic. Here is how it's declared::

    pResult analyze(const mana::PE& pe);

It's return type has been covered already, but what about the argument? This ``PE`` object is all the plugin has to work with, but it contains all the information gathered from the input file's structure. Let's look at some examples:

DOS Header
----------

The DOS header can be retreived through the ``get_dos_header()`` function::

    auto pdos = pe.get_dos_header();
    if (pdos != nullptr) {
        std::cout << pdos->e_cblp << std::endl;
    }

The return value is a pointer to an instance of the following structure, which matches the Windows standard::

    typedef struct dos_header_t
    {
        boost::uint8_t  e_magic[2];
        boost::uint16_t e_cblp;
        boost::uint16_t e_cp;
        boost::uint16_t e_crlc;
        boost::uint16_t e_cparhdr;
        boost::uint16_t e_minalloc;
        boost::uint16_t e_maxalloc;
        boost::uint16_t e_ss;
        boost::uint16_t e_sp;
        boost::uint16_t e_csum;
        boost::uint16_t e_ip;
        boost::uint16_t e_cs;
        boost::uint16_t e_lfarlc;
        boost::uint16_t e_ovno;
        boost::uint16_t e_res[4];
        boost::uint16_t e_oemid;
        boost::uint16_t e_oeminfo;
        boost::uint16_t e_res2[10];
        boost::uint32_t e_lfanew;
    } dos_header;

PE Header
---------

The ``get_pe_header()`` function can be used to query the PE header::

    auto ppe_header = pe.get_pe_header();
    if (ppe_header != nullptr && ppe_header->NumberofSections > 4) {
        // ...
    }

The return value is a pointer to an instance of the following structure, which matches the Windows standard::

    typedef struct pe_header_t
    {
        boost::uint8_t  Signature[4];
        boost::uint16_t Machine;
        boost::uint16_t NumberofSections;
        boost::uint32_t TimeDateStamp;
        boost::uint32_t PointerToSymbolTable;
        boost::uint32_t NumberOfSymbols;
        boost::uint16_t SizeOfOptionalHeader;
        boost::uint16_t Characteristics;
    } pe_header;

Optional Header
---------------

If you need to access data contained in the PE optional header, ``get_image_optional_header()`` is the function you should use::

    auto popt = pe.get_image_optional_header();
    if (popt != nullptr && popt->Magic ==0x10b) {
        // ...
    }

The return value is a pointer to an instance of the following structure, which matches the Windows standard::

    typedef struct image_optional_header_t
    {
        boost::uint16_t Magic;
        boost::uint8_t  MajorLinkerVersion;
        boost::uint8_t  MinorLinkerVersion;
        boost::uint32_t SizeOfCode;
        boost::uint32_t SizeOfInitializedData;
        boost::uint32_t SizeOfUninitializedData;
        boost::uint32_t AddressOfEntryPoint;
        boost::uint32_t BaseOfCode;
        boost::uint32_t BaseOfData;
        boost::uint64_t ImageBase;
        boost::uint32_t SectionAlignment;
        boost::uint32_t FileAlignment;
        boost::uint16_t MajorOperatingSystemVersion;
        boost::uint16_t MinorOperatingSystemVersion;
        boost::uint16_t MajorImageVersion;
        boost::uint16_t MinorImageVersion;
        boost::uint16_t MajorSubsystemVersion;
        boost::uint16_t MinorSubsystemVersion;
        boost::uint32_t Win32VersionValue;
        boost::uint32_t SizeOfImage;
        boost::uint32_t SizeOfHeaders;
        boost::uint32_t Checksum;
        boost::uint16_t Subsystem;
        boost::uint16_t DllCharacteristics;
        boost::uint64_t SizeofStackReserve;
        boost::uint64_t SizeofStackCommit;
        boost::uint64_t SizeofHeapReserve;
        boost::uint64_t SizeofHeapCommit;
        boost::uint32_t LoaderFlags;
        boost::uint32_t NumberOfRvaAndSizes;
        image_data_directory directories[0x10];
    } image_optional_header;

Sections
--------

You can iterate on the input file's sections using the ``get_sections()`` function::

    auto psections = pe.get_sections();
    if (psections != nullptr)
    {
        for (auto it = psections->begin() ; it != psections->end() ; ++it) {
            // ...
        }
    }

The return value is a shared vector of Section objetcts, which are described later on this page.

Imports
-------

In Manalyze, looking up imports is a two-step process. You usually query the list of DLLs imported by the PE first, then look up particular functions imported in a given DLL. Here is how you would list all the imported DLLs for a PE, using ``get_imported_dlls`` and ``get_imported_functions``::

    auto dlls = pe.get_imported_dlls();
    if (dlls == nullptr) {
        return;
    }
    for (auto dll = dlls->begin() ; dll != dll->end() ; ++dll)
    {
        auto functions = pe.get_imported_functions(dll);
        if (functions == nullptr) {
            continue;
        }
        std::cout << dll << ":" << std::endl;
        for (auto f = functions->begin() ; f != functions->end() ; ++f) {
            std::cout << "\t" << f << std::endl;
        }
    }

You can also use the ``find_imports`` and ``find_imported_dlls`` function if you're looking for something specific. For instance::

	auto dlls = pe.find_imports("WS2_32.dll", false);
	
...will return all shared libraries imported by the PE matching the regular expression given as the first argument. The second argument controls whether the regular expression is case sensitive and defaults to false when omitted.
	
    auto functions = pe.find_imports(".*basic_ostream.*", "MSVCP\\d{3}.dll|KERNEL32.dll", false);

...where the first argument is a regular expression matching the functions to look for, the second one is a regular expression matching the DLLs to search, and the third one is whether the regular expression is case sensitive. 
You can omit the latter two to look for the requested functions in any DLL with a case insensitive expression::

    auto functions = pe.find_imports(".*bAsIc_OsTrEaM.*"); // Will search in any DLL, case insensitive
	
Finally, if you're interested in looking into the underlying structures, ``pe.get_imports`` returns ``ImportedLibrary`` objects which give direct access to the ``IMAGE_IMPORT_DESCRIPTOR`` and ``IMPORT_LOOKUP_TABLE``.

Exports
-------

You can sift through exported functions with ``get_exports``::

    auto pexports = pe.get_exports();
    if (pexports != nullptr)
    {
        for (auto export = pexports->begin() ; export != pexports->end() ; ++export) {
            std::cout << export->Name << " at ordinal " << export->Ordinal << std::endl;
        }
    }

The function returns a shared vector containing pointers to instances of the following structure::

    typedef struct exported_function_t
    {
        boost::uint32_t Ordinal;
        boost::uint32_t Address;
        std::string        Name;
        std::string        ForwardName;
    } exported_function;

Resources
---------

It s possible to iterate through the input file's resources with the ``get_resources()`` function::

    auto resources = pe.get_resources();
    if (resources != nullptr)
    {
        for (auto r = resources->begin() ; r != resources->end() ; ++r) {
            // ...
        }
    }

The return value is a shared vector of Resource objetcts, which are described later on this page.

Debug Information
-----------------

If debug information is present in the binary, you can access it through the ``get_debug_info`` function::

    auto pdebug = pe.get_debug_info();
    if (pdebug != nullptr)
    {
        for (auto d = pdebug->begin() ; d != pdebug->end() ; ++d) {
            // do something with d->TimeDateStamp
        }
    }

The function returns a shared vector containing pointers to instances of the following structure::

    typedef struct debug_directory_entry_t
    {
        boost::uint32_t    Characteristics;
        boost::uint32_t    TimeDateStamp;
        boost::uint16_t    MajorVersion;
        boost::uint16_t    MinorVersion;
        boost::uint32_t    Type;
        boost::uint32_t    SizeofData;
        boost::uint32_t    AddressOfRawData;
        boost::uint32_t    PointerToRawData;
        std::string        Filename;
    } debug_directory_entry;
	
Thread Local Storage
--------------------

If TLS callbacks are defined in the binary, you can look them up with ``get_tls``::

	auto ptls = pe.get_tls();
	if (tls == nullptr) {
		return; // No TLS callbacks or failed to parse them.
	}
	for (auto it = tls->Callbacks.begin() ; it != tls->Callbacks.end() ; ++it) {
		std::cout << "Callback address: 0x" << std::hex << *it);
	}
	
The object returned by this function is a pointer to an instance of the following structure::

	typedef struct image_tls_directory_t
	{
		boost::uint64_t					StartAddressOfRawData;
		boost::uint64_t					EndAddressOfRawData;
		boost::uint64_t					AddressOfIndex;
		boost::uint64_t					AddressOfCallbacks;
		boost::uint32_t					SizeOfZeroFill;
		boost::uint32_t					Characteristics;
		std::vector<boost::uint64_t>			Callbacks; // Non-standard!
	} image_tls_directory;
	
It closely resembles the original IMAGE_TLS_DIRECTORY structure, but with a list of all the callback addresses already parsed and stored in the ``Callbacks`` vector for your convinience.
	
Load Configuration
------------------

You can query the load configuration of the PE with the following function::

	auto pconfig = pe.get_config();
	if (pconfig != nullptr && config->SecurityCookie == 0) {
		std::cout << "/GS seems to be disabled!" << std::endl;
	}
	
The structure returned by this function mirrors the one defined in the `MSDN <https://msdn.microsoft.com/en-us/library/windows/hardware/ff549596(v=vs.85).aspx>`_::

	typedef struct image_load_config_directory_t
	{
		boost::uint32_t	Size;
		boost::uint32_t	TimeDateStamp;
		boost::uint16_t	MajorVersion;
		boost::uint16_t	MinorVersion;
		boost::uint32_t GlobalFlagsClear;
		boost::uint32_t GlobalFlagsSet;
		boost::uint32_t CriticalSectionDefaultTimeout;
		boost::uint64_t DeCommitFreeBlockThreshold;
		boost::uint64_t DeCommitTotalFreeThreshold;
		boost::uint64_t LockPrefixTable;
		boost::uint64_t MaximumAllocationSize;
		boost::uint64_t VirtualMemoryThreshold;
		boost::uint64_t ProcessAffinityMask;
		boost::uint32_t ProcessHeapFlags;
		boost::uint16_t CSDVersion;
		boost::uint16_t Reserved1;
		boost::uint64_t EditList;
		boost::uint64_t SecurityCookie;
		boost::uint64_t SEHandlerTable;
		boost::uint64_t SEHandlerCount;
	} image_load_config_directory;
	
Delay Load Table
----------------

For PE files which have delayed imports, the ``DELAY_LOAD_DIRECTORY_TABLE`` can be retreived through ``get_delay_load_table``::

	auto dldt = pe.get_delay_load_table();
	if (dldt == nullptr) {
		return; // No delayed imports.
	}
	std::cout << dldt->NameStr << " is delay-loaded!" << std::endl;

The function returns a pointer to the following structure::

	typedef struct delay_load_directory_table_t
	{
		boost::uint32_t Attributes;
		boost::uint32_t Name;
		boost::uint32_t ModuleHandle;
		boost::uint32_t DelayImportAddressTable;
		boost::uint32_t DelayImportNameTable;
		boost::uint32_t BoundDelayImportTable;
		boost::uint32_t UnloadDelayImportTable;
		boost::uint32_t TimeStamp;
		std::string		NameStr; // Non-standard!
	} delay_load_directory_table;

RICH Header
-----------

The RICH header can be can be obtained with the ``get_rich_header`` function::

	auto rich = pe.get_rich_header();
	if (rich == nullptr) {
		return; // No RICH header.
	}
	std::cout << "XOR key: " << rich->xor_key << std::endl;
	std::cout << "File offset: " << rich->file_offset << std::endl;
	for (auto v : rich->values)	{
		std::cout << "Type: " << std::get<0>(v) << " - Prodid: " << std::get<1>(v) << " - Count: " << std::get<2>(v) << std::endl;
	}
	
As there is no official documentation for this structure, it is defined like this in Manalyze::

	typedef struct rich_header_t
	{
		boost::uint32_t xor_key;
		boost::uint32_t file_offset;
		// Structure : id, product_id, count
		std::vector<std::tuple<boost::uint16_t, boost::uint16_t, boost::uint32_t> > values;
	} rich_header;

The `file_offset` field is the absolute position in bytes of the structure in the file (usually ``0x80``). For more information regarding the origin of this structure and what information is contained in it, you can consult `this article <http://www.ntcore.com/files/richsign.htm>`_.
	
Miscellaneous
-------------

``pe.get_filesize()`` returns the size of the input file in bytes.

``pe.get_architecture()`` returns either ``PE::x86`` or ``PE::x64`` depending on the program's target architecture.

``pe.rva_to_offset(boost::uint64_t rva)`` translates a relative virtual address into a file offset.

``pe.get_raw_bytes(size_t size)`` returns the ``size`` first raw bytes of the file. If ``size`` is omitted, every byte from the file is returned::

	auto bytes = pe.get_raw_bytes(1000);
	for (auto it = bytes->begin() ; it != bytes->end() ; ++it) {
		// Iterate on the bytes...
	}
	// Or access them directly:
	if ((*bytes)[0] == 'M' && &(*bytes)[1] == 'Z') { ... }

``pe.get_overlay_bytes(size_t size)`` returns the ``size`` first bytes of the overlay data of the PE. If ``size`` is omitted, every byte from the overlay data is returned; and if the file contains no such data, ``nullptr`` is returned.
	
``nt::translate_to_flag`` and ``nt::translate_to_flags`` are two functions that come in handy when you need to expand flags (i.e. the ``Characteristics`` field of many structures). Use the first function for values which translate into a single flag, and the second one for values which are composed of multiple ones::

    auto pType = nt::translate_to_flag(ppe_header->Machine, nt::MACHINE_TYPES);
    if (pType != nullptr) {
        std::cout << "Machine type: " << *pType << std::endl;
    }

The first argument is of course the value to translate, while the second is a map describing all the flags. Dictionaries relevant to PE structures can be found in ``manape/nt_values.cpp`` in the ``nt`` namespace. You can also define your own like this::

    import "manape/pe.h"

    const nt::flag_dict MY_DICT = boost::assign::map_list_of("Value 1", 0x0)
                                                            ("Value 2", 0x1)
                                                            // ...
                                                            ("Value F", 0xF);

Results are returned as a shared string or a shared vector of strings respectively.

Section objects
===============

Section objects represent sections of a PE executable. They are very close to the structures defined in the norm, but have been enriched with a couple of utility functions.

``get_name``, ``get_virtual_size``, ``get_virtual_address``, ``get_size_of_raw_data``, ``get_pointer_to_raw_data``, ``get_pointer_to_relocations``, ``get_pointer_to_line_numbers``, ``get_number_of_relocations``, ``get_number_of_line_numbers`` and ``get_characteristics`` are simple accessors to all the standard information describing a section.

In addition, a ``get_entropy`` function was added to determine the entropy of a section.

Finding a section
-----------------

A ``find_section`` function is available to locate a section based on a relative virtual address (RVA)::

	mana::image_optional_header ioh = *pe.get_image_optional_header();
	mana::pSection sec = mana::find_section(ioh.AddressOfEntryPoint, *pe.get_sections());
	if (sec != nullptr) {
		std::cout << "Found section: " << *sec->get_name() << std::endl;
	}

The first argument is a RVA which is contained in the section to locate, while de second one is a list of candidate sections (it will almost always be the return value of ``pe.get_sections``).

Conversely, you can check whether an address belongs to a specific section with the following function::

    bool is_address_in_section(boost::uint64_t rva, mana::pSection section, bool check_raw_size = false);

The last argument can be used to perform the check by taking the raw size of the section into account instead of the virtual size, which may be useful for some malformed PEs.

Accessing the raw bytes
-----------------------

If you need to perform some processing on the section's bytes, use ``get_raw_data()``. Be aware that the whole section will be loaded in memory, so you may encounter problems when processing very big files::

	mana::pSection sec = mana::find_section(ioh.AddressOfEntryPoint, *pe.get_sections());
	if (sec != nullptr)
	{
		mana::shared_bytes bytes = sec->get_raw_data();
		for (auto it = bytes->begin() ; it != bytes->end() ; ++it)
		{
			// ...
		}
	}

Resource objects
================

In Manalyze, PE resources are represented as Resource objects that can be manipulated similarly to Sections. ``get_name``, ``get_type``, ``get_language``, ``get_codepage``, ``get_size``, ``get_id`` and ``get_offset`` provide access to basic information and ``get_entropy`` calculates the entropy of the resource.

Accessing the underlying resource
---------------------------------

Most of the time, you'll want to look at the actual resource bytes. A ``get_raw_bytes`` function is provided and can be used just like the one described above in the context of sections. Some PE resources however have a well-known structure and can be converted into C++ objects to be reused immediately. This is where the function ``template <class T> T interpret_as();`` comes in. Depending on the template parameter, here are the resource types you can handle:

* ``pString`` for ``RT_MANIFEST`` resources. The contents of the PE manifest are returned as a shared string::

		if (*resource->get_type() == "RT_MANIFEST")
		{
			pString rt_manifest = r->interpret_as<pString>();
			if (rt_manifest != nullptr) {
				std::cout << "Manifest contents: " << *rt_manifest << std::endl;
			}
		}

* ``const_shared_string`` for ``RT_STRING``: the strings contained in the resource are returned as a shared vector. ::

		if (*resource->get_type() != "RT_STRING") {
			return;
		}
		auto string_table = resource->interpret_as<const_shared_strings>();
		std::wcout << L"Dumping a RT_STRING resource:" << std::endl;
		for (auto it = string_table->begin() ; it != string_table->end() ; ++it) {
			std::wcout << *it << std::endl;
		}
		
	The strings returned are UTF-8 encoded.

* ``pgroup_icon_directory`` for ``RT_GROUP_ICON`` and ``RT_GROUP_CURSOR``. Because of the way icons and cursors are stored in resources, an additional function ``reconstruct_icon`` was added to recreate a valid ICO file. Here is how you'd do it::

		if (*res->get_type() == "RT_GROUP_ICON" || *res->get_type() == "RT_GROUP_CURSOR") {
			ico_file = reconstruct_icon((*it)->interpret_as<pgroup_icon_directory>(), *pe.get_resources());
		}
		FILE* f = fopen("icon.ico", "wb");
		if (f == nullptr) {
			return;
		}
		fwrite(&ico_file[0], 1, ico_file->size(), f);
		fclose(f);

* ``pbitmap`` for a ``RT_BITMAP``.
* ``pversion_info`` for ``RT_VERSIONINFO`` resources.
* And finally ``shared_bytes`` for any resource type, which will behave exactly like ``get_raw_data``.

All these functions will return null pointers if for some reason the resource cannot be interpreted as the requested type.

Extracting resources
--------------------

Utility functions are provided to extract resources into a file. Use `extract` or `icon_extract` depending on the resource type - the reason why two separate functions were written is that icon data may be spread over multiple resources, therefore a list of all the resources of the PE must be provided to reconstruct them properly. Here is how you can extract resources in the general case::

	auto resources = pe.get_resources();
	for (auto it = resources->begin() ; it != resources->end() ; ++it)
	{
		bool res;
		if (*(*it)->get_type() == "RT_GROUP_ICON" || *(*it)->get_type() == "RT_GROUP_CURSOR") {
			res = (*it)->icon_extract(*(*it)->get_name() + ".ico", resources);
		}
		else {
			res = (*it)->extract(*(*it)->get_name() + ".bin");
		}

		if (!res) {
			std::cerr << "Resource extraction failed :(" << std::endl;
		}
	}

.. note:: What's up with all these pointers?
	
	Manalyze is built statically on Windows for a number of reasons which go beyond the scope of this documentation. This causes some issues when functions are called across DLLs, issues which can only be resolved through smart pointers ensuring that a module which allocated an object will be the one to free it. This ends up making all the interfaces a little more complex by having pointers everywhere.
	
Using the configuration file
============================

If you want to give users additional control on the plugin's behavior, you can let them pass arguments through the configuration file, ``manalyze.conf``. For instance, this mechanism is used to provide a VirusTotal API key without having to hard-code it into the software. Each plugin has access to a protected ``_config`` variable through its parent class. It is a simple map between strings. Here is an example of how it is used, taken from the packer detection plugin::

	unsigned int min_imports;
	// Check that a value was set in the configuration, otherwise use a default one.
	if (_config == nullptr || !_config->count("min_imports")) {
		min_imports = 10;
	}
	else
	{
		try {
			min_imports = std::stoi(_config->at("min_imports"));
		}
		catch (std::invalid_argument) // In case someone writes "packer.min_imports = ABC"
		{
			PRINT_WARNING << "Could not parse packer.min_imports in the configuration file." << std::endl;
			min_imports = 10;
		}
	}
	
Using variables from the configuration doesn't require any additional work: lines added to the configuration files are automatically parsed and provided to the target plugin. Let's assume you add the following lines to the configuration file::

	helloworld.msg = Hello World!
	# Lines starting with # are comments, the parser ignores them.
	helloworld.val = 0
	
...then the ``_config`` variable of a plugin whose name (as reported by the ``get_id`` function) is ``helloworld`` would contain the following map::

	{
		"msg":	"Hello World!",
		"val":	"0" // Careful! That's still a string!
	}

.. note:: The configuration is only initialized before calling the ``analyze`` method. This means that you won't be able to reference your plugin's configuration from its constructor.
	
Anything missing?
=================

If you are trying to do something but still can't figure out how to do it, be sure to get in touch with the project's maintainer via `GitHub <https://github.com/JusticeRage/Manalyze/issues>`_. Possible problems might include:

* API not providing access to data you need.
* Some part of the PE being parsed incorrectly or insufficiently.
* The documentation not being clear enough on a particular topic.
