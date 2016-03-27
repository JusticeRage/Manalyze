*********************
Reusing the PE parser
*********************

This section will explain how you can take the PE parser (ManaPE) out of Manalyze and re-use it in another project. We will focus on Linux environments, but the instructions given here should be easy to apply to other systems.

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

Obviously, you'll want to write a Makefile or use CMake, but this should be enough to get you started. If you need detailed information on available methods that you can use from here, please see this section on by :ref:`pe_objects`.
