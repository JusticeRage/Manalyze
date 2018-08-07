*****
Usage
*****

If you have managed to :doc:`obtain <obtaining-manalyze>` and :doc:`configure <initial-configuration>` Manalyze but want to know more about how to use it, you're in the right place! First, let's have a look at the program's help screen::

    Usage:
      -h [ --help ]         Displays this message.
      -v [ --version ]      Prints the program's version.
      --pe arg              The PE to analyze. Also accepted as a positional
                            argument. Multiple files may be specified.
      -r [ --recursive ]    Scan all files in a directory (subdirectories will be
                            ignored).
      -o [ --output ] arg   The output format. May be 'raw' (default) or 'json'.
      -d [ --dump ] arg     Dump PE information. Available choices are any
                            combination of: all, summary, dos (dos header), pe (pe
                            header), opt (pe optional header), sections, imports,
                            exports, resources, version, debug, tls, config, delay
      --hashes              Calculate various hashes of the file (may slow down the
                            analysis!)
      -x [ --extract ] arg  Extract the PE resources to the target directory.
      -p [ --plugins ] arg  Analyze the binary with additional plugins. (may slow
                            down the analysis!)

    Available plugins:
      - clamav: Scans the binary with ClamAV virus definitions.
      - compilers: Tries to determine which compiler generated the binary.
      - peid: Returns the PEiD signature of the binary.
      - strings: Looks for suspicious strings (anti-VM, process names...).
      - findcrypt: Detects embedded cryptographic constants.
      - packer: Tries to structurally detect packer presence.
      - imports: Looks for suspicious imports.
      - resources: Analyzes the program's resources.
      - mitigation: Displays the enabled exploit mitigation techniques (DEP, ASLR, etc.).
      - authenticode: Checks if the digital signature of the PE is valid.
      - virustotal: Checks existing AV results on VirusTotal.
      - all: Run all the available plugins.

    Examples:
      manalyze.exe program.exe
      manalyze.exe -dresources -dexports -x out/ program.exe
      manalyze.exe --dump=imports,sections --hashes program.exe
      manalyze.exe -r malwares/ --plugins=peid,clamav --dump all

Most options are self-explanatory, but let's go over them anyway.

Selecting target programs
=========================

In order to choose which program(s) should be analyzed, you can use the ``--pe`` option. Targets are also accepted as positional arguments; this means that listing them on the command line without prefixing them with any particular flag will work. You can specify as many files as you want: they will be studied sequentially. The ``-r`` (or ``--recursive``) option allows you to scan whole directories - even if they contain gigabytes of files (have fun reading the reports though). However, subdirectories will be ignored. For instance, if you have the following folder structure::

    dir/
       |- malware1.exe
       |- lib1.dll
       `- dropped/
           |- malware2.exe
           `- lib2.dll

...then running a recursive analysis on this folder will **not** process malware2.exe and lib2.dll. Use ``./manalyze -r dir dir/dropped`` to analyze all of them.

Dumping a PE's structure
========================

Since Manalyze implements a PE parser, you can use it to look closely at the structure of target files. the ``--dump`` (or ``-d``) option allows you to control what part of the PE you want to print. For instance, to look at a PE's sections, use ``./manalyze [target file] -d sections``. You can of choose to display several categories at once. In terms of syntax, ``./manalyze [target file] -d sections -d imports`` and ``./manalyze [target file] -d sections,imports`` are equivalent.

Here is the list of all supported categories:

* **summary**: Contains general information on the input file. It gathers all the metadata which may be relevant to the interests of a malware researcher: possible debug paths present in the binary, a list of detected resource and/or manifest languages, compilation date, etc.
* **dos**, **pe**, **opt**: The DOS, PE, and PE optional headers respectively.
* **sections**; The sections of the PE. Note that if the ``--hashes`` option has been set, the returned information will also contain the hashes of each section.
* **imports** and **exports**: The imported functions and exported functions of the input file.
* **resources**: Displays information about the resources included in target PE files (size, entropy, filetype if possible, etc.). Cryptographic hashes will also be displayed if the ``--hashes`` option was activated. You may also be interested in the companion ``--extract`` (or ``-x``) option, which allows you to write the resources inside the folder of your choice. Note that it is of course possible to extract resources without printing information about them, and vice-versa.
* **version**, **debug** and **tls**: These categories respectively show the data contained in the ``RT_VERSION`` resource, some metadata about embedded debug information and possible TLS callbacks.
* **all**: Dump everything.

If the requested data is not present (for instance, if no TLS callbacks are present in the input file), Manalyze simply won't return anything for the requested category. If no category is requested, the program will display the summary information by default. Finally, in addition to the uses described above, the ``--hashes`` option will also print the file hashes (MD5, SHA1, SHA256, SHA3, imphash and ssdeep) if given.

Using the plugins
=================

While reading raw PE data may be interesting, Malalyze was designed so that tools could process this information automatically and generate meaningful reports based on them. The basic workflow of the project goes like this:

1. The PE parser gathers as much data as possible on a given input file.
2. The obtained data is provided to plugins so they can study, mine and/or correlate it to give an opinion about whether a program is malicious or not, or simply print out information which would be relevant to someone analyzing the file.

The following plugins are available:

* **clamav**: Applies ClamAV signatures to detect known malware. In order to use this plugin, make sure that you have :doc:`downloaded the signatures <initial-configuration>`!
* **compilers**: Applies PEiD signatures to try to detect the compiler which generated the input file.
* **strings**: Looks for suspicious strings and patterns inside the binary (i.e. references to ``cmd.exe``, anti-VM opcodes, etc.).
* **findcrypt**: Detects cryptographic capabilities in a binary by looking at imports and searching for constants used in well-known algorithms.
* **packer**: Applies PEiD signatures to try to detect if the file was packed. Warnings will also be raised based on unusual section names and a low number of imports (which can be set in the configuration file to better suit your needs).
* **imports**: Guesses a PE file's capabilities through its imported functions.
* **resources**: Analyzes a program's resources to see if it contains encrypted files and/or suspicious filetypes. This plugin also contains a couple of heuristic methods to determine if a file might be a `dropper <https://en.wikipedia.org/wiki/Dropper_%28malware%29>`_.
* **mitigation**: Checks which exploit mitigation techniques (/GS, SafeSEH, ASLR and DEP) are enabled in the binary.
* **authenticode**: Checks the validity of a PE file's signature. At the moment, this plugin is only available on Windows platforms, since it relies heavily on that operating system's API.
* **virustotal**: Submits the hash of the input file to VirusTotal to see if any antivirus engine detects it as malware.
* **all**: Run all plugins.

Installing plugins
------------------

I'm not aware of any third-party plugins at the moment, but should anyone develop one, all you have to do to use it is download the ``.dll`` or ``.so`` file (depending on your OS) and place it next to Manalyze's binary. It will be detected automatically.
