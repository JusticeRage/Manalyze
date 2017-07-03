*********************
Reusing the PE parser
*********************

Embedding the code
==================

This section will explain how you can take the PE parser (ManaPE) out of Manalyze and re-use it in another project. 

Let's start by writing some sample code that would read a PE file using Manalyze's parser::

	#include <iostream>
	#include "manape/pe.h"

	int main(int argc, char** argv)
	{
		mana::PE pe("file.exe");
		if (pe.is_valid()) { // Always check this.
			std::cout << "File parsed successfully: " << *pe.get_path() << std::endl;
		}
		else
		{
			std::cout << "The file is invalid!" << std::endl;
			return 1;
		}

		// Do stuff with the PE
		auto sections = pe.get_sections();
		for (auto it = sections->begin() ; it != sections->end() ; ++it) {
			std::cout << *(*it)->get_name() << std::endl;
		}
		// ...

		return 0;
	}

For this to compile, you'll have to grab ManaPE's code and put it inside your project. you need both the ``manape`` and ``include/manape`` folders. ::

	~/code/project$ mkdir include
	~/code/project$ cp -r [...]/Manalyze/manape/ . && cp -r [...]/Manalyze/include/manape/ include/

You don't have to follow the same folder structure, it's only given as an example. Then, assuming you copied the previous code in ``main.cpp``, the only thing left to do is to compile everything::

	~/code/project$ g++ main.cpp manape/*.cpp -lboost_system -lboost_regex -Iinclude -std=c++11
	~/code/project$ ./a.out 
	File parsed successfully: file.exe
	.text
	.rdata
	.data
	.rsrc

Obviously, you'll want to write a Makefile or use CMake, but this should be enough to get you started. If you need detailed information on available methods that you can use from here, please see this section on :ref:`pe_objects`.

Reusing binaries
================

On Linux
--------

Depending on your use-case, you may alternatively re-use the shared libraries which are distributed and/or generated with Manalyze and its build system.

In that case, you still have to include the header files in your project as described above (except you only need the ``[...]/Manalyze/include/manape/`` directory). You also need to copy the shared objects::

	~/code/project$ mkdir include lib
	~/code/project$ cp -r [...]/Manalyze/include/manape/ include/
	~/code/project$ cp [...]/Manalyze/bin/*.so lib/
	
Subsequently, add ``-Llib`` and ``-lmanape -lmanacommons`` to your compilation flags to indicate that the compiler should link against those libraries.

On Windows
----------

Linking against DLLs requires a little more work on Windows. First, copy Manalyze's header files in your project directory as described above. Also put Manalyze's DLLs somewhere in the PATH of your project (likely the folder where your executable will be generated). You'll need ``manape.dll``, ``manacommons.dll``, ``hash-library.dll`` and ``yara.dll``.

Sadly, Visual Studio is *only* capable of linking against ``.lib`` files, even if the code will *in fine* be found in a DLL. Those files are generated when Manalyze is built but are not distributed with the program - this means that you have to checkout Manalyze's source code from GitHub and build it manually. Hopefully, this should be as simple as this::

	$ git clone https://github.com/JusticeRage/Manalyze.git
	$ cd Manalyze
	$ cmake .

...Then use Visual Studio to build everything. Following that, you will find a few ``.lib`` files in ``[...]\Manalyze\Debug\`` or ``[...]\Manalyze\Release\`` (use whichever matches your build profile). Copy ``*.lib`` to a ``lib`` folder in your project directory and configure VS so that they will be taken into account. This involves:

- Adding the ``lib`` folder to ``Library Directories`` under ``VC++ Directories``.
- Specifying ``manape.lib`` and ``manacommons.lib`` in ``Linker > Input > Additional Dependencies``

From there, you should be able to write code relying on the PE parser!
