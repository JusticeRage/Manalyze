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

  * `CMake <https://cmake.org/>`_
  * A recent version of `Boost <http://www.boost.org/>`_.
  
2. Checkout the program's source code from GitHub.
3. Using CMake to generate system-dependent build files. The CMake script will also check out additional libraries from GitHub.
4. Compile Manalyze. All the binaries are placed in the ``bin/`` folder.

Here are more specific steps for a few major operating systems:

Linux and BSD
-------------

How you take care of step 1 may vary depending on your package manager. On Debian Jessie, use the following command **as root**::

    apt-get install libboost-regex-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev build-essential cmake git
	
On FreeBSD 10.2, use this one instead (also **as root**)::

    pkg install boost-libs-1.55.0_8 cmake git
	
Next, get Manalyze's source code and try building it::

    git clone https://github.com/JusticeRage/Manalyze.git && cd Manalyze
    cmake .
    make
    cd bin && ./manalyze --version

If everything went well, the tool's version should be displayed. Otherwise, look for error messages during the build process and get in touch with the maintainer to request help!

Windows
-------

Step 1 requires a bit more work on Windows, because the Boost libraries have to be built manually.

* First, get the latest version on the `official website <http://www.boost.org/users/download/>`_ and extract them somewhere (for instance, ``C:\code\boost_1_XX_0\``). Open a command prompt and navigate to that folder.
* Run the following command to build the required libraries:
  ::
    ./bootstrap.bat && ./b2.exe --build-type=complete --with-regex --with-program_options --with-system --with-filesystem
* Set up the ``BOOST_ROOT`` environment variable to help CMake locate the libraries you just built. In this example, the environment variable should contain: ``C:\code\boost_1_XX_0\``.
* Finally, if you haven't done it already, don't forget to install `CMake <https://cmake.org/download/>`_ and `Git <https://git-scm.com/download/win>`_.

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