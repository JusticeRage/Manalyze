******************
Obtaining the tool
******************

Binary distributions
====================

Windows users can download the latest binaries `here <https://manalyzer.org/static/manalyze.rar>`_. Unzip the archive somewhere on your filesystem and you're ready to go! All the binaries are signed with a certificate presenting the following fingerprint : ``26fc24c12b2d84f77615cf6299e3e4ca4f3878fc``.

Deb packages will hopefully be offered at some point but right now, using Manalyze on other operating systems requires compiling it yourself.

Building Manalyze
=================

Spending hours trying to build someone else's code is one of the most horrendous experiences in software development. A lot of work was put into Manalyze's build system to ensure that anyone would be able to compile it with a minimum of friction. If the following instructions don't work for you, be sure to get in touch with the program's maintainer so the situation (or this documentation) can be improved.

In the general case, you can build this tool in four simple steps:

1. Obtaining the tools and libraries Manalyze depends on:

  * `CMake <https://cmake.org/download/>`_
  * A recent version of `Boost <http://www.boost.org/users/download/>`_.
  
2. Checkout the program's source code from GitHub.
3. Using CMake to generate system-dependent build files. The CMake script will also check out additional libraries from GitHub.
4. Compile Manalyze. All the binaries are placed in the ``bin/`` folder.

Here are more specific steps for a few major operating systems:

Linux and BSD
-------------

How you take care of step 1 may vary depending on your package manager. On Debian Jessie, use the following command **as root**::

    apt-get install libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libssl-dev build-essential cmake git
	
On FreeBSD 10.2, use this one instead (also **as root**)::

    pkg install boost-libs-1.55.0_8 libressl cmake git
	
Next, get Manalyze's source code and try building it::

    git clone https://github.com/JusticeRage/Manalyze.git && cd Manalyze
    cmake .
    make
    cd bin && ./manalyze --version

If everything went well, the tool's version should be displayed. Otherwise, jump to the `Troubleshooting`_ section below or look for error messages during the build process and get in touch with the maintainer to request help!

.. TIP:: You can enable debug builds with the following command: ``cmake . -DDebug=ON``

Windows
-------

Step 1 requires a bit more work on Windows, because the Boost libraries have to be built manually.

* First, get the latest version on the `official website <http://www.boost.org/users/download/>`_ and extract them somewhere (for instance, ``C:\code\boost_1_XX_0\``). Open a command prompt and navigate to that folder.
* Run the following command to build the required libraries:
  ::

    ./bootstrap.bat && ./b2.exe --build-type=complete --with-regex --with-program_options --with-system --with-filesystem
* Set up the ``BOOST_ROOT`` environment variable to help CMake locate the libraries you just built. In this example, the environment variable should contain: ``C:\code\boost_1_XX_0\``.
* Finally, if you haven't done it already, don't forget to install `CMake`_ and `Git <https://git-scm.com/download/win>`_.

That's it for the dependencies. Steps 2 and 3 can be tackled with a single command::

    git clone https://github.com/JusticeRage/Manalyze.git && cd Manalyze && cmake .
	
Build files should have appeared in Manalyze's folder. Usually, they take the form of a Visual Studio project (i.e. ``manalyze.sln``). Double-click it to open it in the IDE, or run the following command inside a Visual Studio command prompt::

    msbuild manalyze.sln

Binaries will appear in the ``bin\`` folder.

What about MacOS?
-----------------
I do not own any Apple hardware, so the tool has never been built - let alone tested - on MacOS yet.

Offline builds
==============

If you need to build Manalyze on a machine which doesn't have internet access, a couple of additional steps are required to manually obtain the libraries that the CMake script would normally obtain. Use the following commands to get the tool's source code::

    git clone https://github.com/JusticeRage/Manalyze.git
    cd Manalyze/external
    git clone https://github.com/JusticeRage/hash-library.git
    git clone https://github.com/JusticeRage/yara.git

Now take the whole ``Manalyze`` folder to the computer on which you intend to build the software (note that this computer still needs the Boost libraries and CMake). Now run the following command to tell the CMake script that it should not try to checkout or update the external libraries::

    cmake . -DGitHub=OFF
	
...and continue as you normally would.

Troubleshooting
===============

This section lists some common compilation errors you may face when building Manalyze, along with their solution.

1. Boost is obsolete
--------------------

This compilation error is usually encountered on Debian 7 (Wheezy)::

	In file included from ~/Manalyze/manacommons/escape.cpp:18:0:
	~/Manalyze/include/manacommons/escape.h:115:97: error: macro "BOOST_STATIC_ASSERT" passed 3 arguments, but takes just 1
	~/Manalyze/include/manacommons/escape.h:148:66: error: macro "BOOST_STATIC_ASSERT" passed 2 arguments, but takes just 1
	~/Manalyze/include/manacommons/escape.h: In function ‘io::pString io::_do_escape(const string&)’:
	~/Manalyze/include/manacommons/escape.h:115:2: error: ‘BOOST_STATIC_ASSERT’ was not declared in this scope
	~/Manalyze/include/manacommons/escape.h: In function ‘io::pString io::escape(const string&)’:
	~/Manalyze/include/manacommons/escape.h:148:2: error: ‘BOOST_STATIC_ASSERT’ was not declared in this scope
	~/Manalyze/include/manacommons/escape.h: In instantiation of ‘io::pString io::_do_escape(const string&) [with Grammar = io::escaped_string_raw<std::back_insert_iterator<std::basic_string<char> > >; io::pString = boost::shared_ptr<std::basic_string<char> >; std::string = std::basic_string<char>]’:
	~/Manalyze/manacommons/escape.cpp:24:53:   required from here
	~/Manalyze/include/manacommons/escape.h:125:10: error: could not convert ‘nullptr’ from ‘std::nullptr_t’ to ‘io::pString {aka boost::shared_ptr<std::basic_string<char> >}’
	make[2]: *** [CMakeFiles/manacommons.dir/manacommons/escape.cpp.o] Error 1
	make[1]: *** [CMakeFiles/manacommons.dir/all] Error 2
	make: *** [all] Error 2

This issue has been traced to the `Boost libraries <http://www.boost.org/>`_ in Wheezy repositories being too old (1.49.0). You'll need to either upgrade them manually or switch to Debian Jessie.

2. CMake does not find OpenSSL
------------------------------

Some versions of CMake (for instance 3.0.2, present in Debian Jessie's repositories) seem to have trouble locating OpenSSL and generate the following error messages::

	CMake Error at /usr/share/cmake-3.0/Modules/FindOpenSSL.cmake:293 (list):
	  list GET given empty list
	Call Stack (most recent call first):
	  CMakeLists.txt:23 (find_package)

	[...]

	-- Found OpenSSL: /usr/lib/x86_64-linux-gnu/libssl.so;/usr/lib/x86_64-linux-gnu/libcrypto.so (found version ".0.0`") 

Upgrading CMake to the latest release (3.5.2 at the time I'm writing this) solves this issue.

3. Incompatibilities between OpenSSL 1.1 and Boost
--------------------------------------------------

The following error may be encountered on Debian 9 (Stretch)::

    In function ‘bool plugin::vt_api_interact(const string&, const string&, std::__cxx11::string&, plugin::sslsocket&)’: ~/Manalyze/plugins/plugin_virustotal/plugin_virustotal.cpp:276:84: error: ‘SSL_R_SHORT_READ’ was not declared in this scope if (error != boost::asio::error::eof && error.value() != ERR_PACK(ERR_LIB_SSL, 0, SSL_R_SHORT_READ))
	
Starting with Stretch, Debian ships with the 1.1 branch of OpenSSL which is `not compatible <https://github.com/chriskohlhoff/asio/issues/184>`_ with most versions of Boost. It is unclear from which version the problem has been fixed, but a workaround for this issue is to download one of the latest Boost distributions from upstream and build it instead of using the libraries provided by Debian.

