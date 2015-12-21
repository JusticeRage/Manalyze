*************************
How the code is organized
*************************

This project currently has over 8000 lines of code and it may be hard at first to find what you're looking for. This page contains an overview of how the code is organized and will help you figure out where the implementations you need to find are located.

The root folder
===============

Let's start at the root folder of the project. It only contains one important file: ``CMakeLists.txt``, which is CMake's configuration file. If you add new sources in your contribution (as opposed to only modifying existing ones), you will need to edit its contents in order to let the build system know about them. Apart from that, Manalyze's README and its license can be found here.

The ``bin`` folder
==================

This is where generated binaries are put - but it contains a few files even if you haven't compiled the project yet:

    * ``manalyze.conf`` is a configuration file for the program, pre-filled with default values.
    * The ``yara_rules`` folder contains `Yara <https://github.com/plusvic/yara>`_ rules used by the different plugins. You will also find a Python script which generates ClamAV rules by downloading the latest signatures from the official website and converting them to the right format.

The ``external`` folder
=======================

This directory should be mostly empty before you run CMake. It contains the third-party libraries that Manalyze is built against. Those libraries are checked out from GitHub during the compilation process. At the moment, there are two of them:

    * `Hash Library <https://github.com/JusticeRage/hash-library>`_, a set of hashing algorithm implementations authored by `Stephan Brumme <http://create.stephan-brumme.com/hash-library/>`_.
    * `Yara <https://github.com/JusticeRage/yara>`_, the well known pattern matching tool from `plusvic <https://github.com/plusvic/yara.git>`_. A few modifications have been made to this project, which justifies maintaining our own fork:

        * The code has been stripped down to a library (the command-line tool has been removed).
        * This version is built with CMake instead of the original Makefile.
        * A C++ wrapper was added to facilitate Yara's manipulation and integration with Manalyze.
        * All modules have been disabled, and a new one was written so Yara can receive information from Manalyze. In particular, their PE module was replaced since Manalyze already contains a powerful PE parser.

Source folders
==============

The code of the project is spread out in the following folders:

    * ``src``: contains Manalyze's "engine". The entry point of the application is located there (in ``main.cpp``), as well as all the functions tasked with validating the arguments, loading the configuration and the plugins, and of course launching the analysis for each target file.
    * ``manacommons``: a small library which contains functionnality shared between the core and the plugins, for instance what a plugin result or an analysis report should look like, or how to print text in color.
    * ``manape``: all the code related to PE parsing is located in this library.
    * ``plugins``: as you might expect, this folder contains Manalyze's plugins. Some of them are fairly simple and fit in a single .cpp file; others are bigger and are subsequently put in a separate folder.
    * ``include``: in this directory, you will find the headers of all the source files contained in the folders described above. If you want to understand the program's API quickly, it is recommended that you have a look at the files located here: function declarations are thoroughly commented and will give you a good idea of each class' capabilities.

Other folders
=============

	* Inside ``docs``, you will find the reStructured Text which is used to generate this documentation!
	* The ``resources`` folder contains some useful documentation, like the PE format specification.


