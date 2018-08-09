*************************
Interfacing with Manalyze
*************************

Endpoints
=========

If you're working on a tool that could benefit from integrating with Manalyze, there are a few ways you can obtain results from the tool.
The most straightforward one is to parse the output directly::

    manalyze [sample] --dump=... --plugins=... --output=json

If you are not willing or able to use Manalyze on your local machine, the web portal can
provide the same results. You will, however, need to contact the project's maintainer
to obtain an API key.

.. code-block:: python

    import requests
    
    # Submit a file
    f = {'file': open("sample.exe", "rb")}
    data = {'api_key': "[Your API key]"}
    r = requests.post("https://manalyzer.org/api/submit", files=f, data=data)
    print r.text
    
    # Get a report for an existing file (no API key required)
    r = requests.get("https://manalyzer.org/json/1804821148ae7c305d0e5d3463bcbd67")
    print r.text

JSON structure
==============

In both cases, you'll obtain a JSON document which represents the report produced by Manalyze. Their high-level structure is as follows::

    user@machine:~/samples$ manalyze -ojson file1 /tmp/file2
    {
        "/home/user/samples/file1": {
            // Report for file1
        }
        "/tmp/file2": {
            // Report for file2
        }
    }

At the root of the document, you'll find an entry for each file analyzed. If the 
analysis could not complete successfully, no object will be added to the document root.
In the rest of the documentation, only reports for a single file will be used, as 
they all have the exact same structure.

Dump of the PE
--------------

The reports can be viewed as the sum of two parts. First, all the information pertaining
to the file format that Manalyze would print through the :code:`--dump` option. Here is
what that part of the document may look like::

	{
		"ab35c68e263bb4dca6c11e16cd7fb9d8": {
		    "Summary": {
		        "Compilation Date": "2017-Nov-16 22:05:22", 
		        "Detected languages": [
		            "English - United States"
		        ], 
		        "CompanyName": "Sysinternals - www.sysinternals.com"
		        // ...
		    }, 
		    "DOS Header": {
		        "e_magic": "MZ", 
		        "e_cblp": 144
		        // ...
		    }, 
		    "Sections": {
		        ".text": {
		            "MD5": "c151016c0929a571e7a3882e3c292524", 
		            "NumberOfRelocations": 0, 
		            "Characteristics": [
		                "IMAGE_SCN_CNT_CODE", 
		                "IMAGE_SCN_MEM_EXECUTE", 
		                "IMAGE_SCN_MEM_READ"
		            ], 
		            "Entropy": 6.60464
		            // ...
		    }, 
		    "Imports": {
		        "WINTRUST.dll": [
		            "CryptCATEnumerateMember", 
		            "CryptCATEnumerateCatAttr"
		            // ...
		        ], 
		        "VERSION.dll": [
		            "GetFileVersionInfoSizeW", 
		            "VerQueryValueW", 
		            "GetFileVersionInfoW"
		        ]
		        // ...
		    }, 
		    "Resources": {
		        "1": {
		            "Type": "RT_VERSION", 
		            "Language": "English - United States", 
		            "SHA1": "48cf205c2a63018aa56267f95490b0da0156aa6d"
		            // ...
		        }
		        // ...
		    }, 
		    "Hashes": {
		        "MD5": "ab35c68e263bb4dca6c11e16cd7fb9d8"
		        // ...
		    }
		    // ...
	}

This document has been trimmed down a for readability purposes, but links to complete reports are provided below. Here is the list of possible keys you can encounter:

- :code:`Summary` (`example 1 <https://manalyzer.org/json/ab35c68e263bb4dca6c11e16cd7fb9d8>`_)
- :code:`DOS Header` (`example 1 <https://manalyzer.org/json/ab35c68e263bb4dca6c11e16cd7fb9d8>`_)
- :code:`PE Header` (`example 1 <https://manalyzer.org/json/ab35c68e263bb4dca6c11e16cd7fb9d8>`_)
- :code:`Image Optional Header` (`example 1 <https://manalyzer.org/json/ab35c68e263bb4dca6c11e16cd7fb9d8>`_)
- :code:`Sections` (`sample with unprintable section names <https://manalyzer.org/json/0a0ae6454e4e6ca0ee0dc5c6ebee97ba>`_)
- :code:`Imports` (`example 2 <https://manalyzer.org/json/643654975b63a9bb6f597502e5cd8f49>`_, `sample with no imports <https://manalyzer.org/json/28a5471c1c8caeb0fe8525668df34870>`_, `imports with name mangling <https://manalyzer.org/json/d64a8cfc11dedb8c3c5b8a1aaf8bd8b0>`_)
- :code:`Delayed Imports` (`example 3 <https://manalyzer.org/json/14f7fba279e4040cd28ee35b7caefdb2>`_)
- :code:`Exports` (`example 4 <https://manalyzer.org/json/2d378958b6fb6c4bf4177f818f52a2b9>`_)
- :code:`Resources` (`example 2 <https://manalyzer.org/json/643654975b63a9bb6f597502e5cd8f49>`_, `sample with no resources <https://manalyzer.org/json/28a5471c1c8caeb0fe8525668df34870>`_)
- :code:`Version Info` (`example 5 <https://manalyzer.org/json/f72cee733b1a6f30f8c850598d67b50a>`_)
- :code:`Debug Info` (`example 6 <https://manalyzer.org/json/af79f5a331c50cc87f0a5f921ad93b0f>`_)
- :code:`TLS Callbacks` (`example 5 <https://manalyzer.org/json/f72cee733b1a6f30f8c850598d67b50a>`_)
- :code:`Load Configuration` (`example 6 <https://manalyzer.org/json/af79f5a331c50cc87f0a5f921ad93b0f>`_)
- :code:`StringTable` (`example 7 <https://manalyzer.org/json/8fbaac9586f84992d21b1d66b04b8912>`_)
- :code:`RICH Header` (`example 1 <https://manalyzer.org/json/ab35c68e263bb4dca6c11e16cd7fb9d8>`_)
- :code:`Hashes` (`example 1 <https://manalyzer.org/json/ab35c68e263bb4dca6c11e16cd7fb9d8>`_)
- :code:`Plugins` (see below)

You can expect at least the :code:`Summary`, :code:`DOS Header` and :code:`DOS Header` to be present in any valid report. 

You'll notice that JSON documents from the web service may contain an additional :code:`Error` section that contains any message that Manalyze has printed on :code:`stderr`. This will not be done automatically with Manalyze's JSON output, so you should capture :code:`stderr` manually if you're interested in errors and warnings.

Plugins
-------

The reports also contain a whole section dedicated to the output of any plugin called by Manalyze. As plugins are more dynamic by nature (users may have downloaded some from third-parties or developed their own), it is not possible to provide an exhaustive list of possible sections. However, all plugin results adhere to the same structure::

	"plugin name": {
		"level": 3, 
		"plugin_output": {
		    "key 1": [
		        "value 1", 
		        "value 2"
		        // ...
		    ],
		    "key 2": "value 3"
		    // ...
		}, 
		"summary": "A single string"
	}

The :code:`level` is an integer value which describes the threat level reported by the plugin. Four values are possible:

- 0: The plugin indicates that the file is harmless (:code:`SAFE`).
- 1: The information gathered is interesting but does not indicate that the file is either goodware or malware (:code:`NO_OPINION`).
- 2: The file contains elements that can be indicative of malicious behavior (:code:`SUSPICIOUS`).
- 3: The sample exhibits characteristics that are generally found in malicious programs only. (:code:`MALICIOUS`).

Keep in mind that each plugin has a very narrow scope and that it's not unexpected to have conflicting plugin verdicts (for instance, a PE file which is both packed and signed would be flagged as safe by the authenticode plugin and malicious by the packer plugin).

Then, the :code:`plugin_output` is an optional series of key-value pairs that can be freely filled by the plugin. Note that the value can be of any type (string, integer, or even lists of strings!). You'll also notice that some keys have a names such as :code:`info_0`. Those names are generated automatically by Manalyze when the plugin doesn't specify one and can be safely ignored for any display purposes. Finally, the :code:`summary` is a high-level description of the plugin's verdict.

Here is a sample plugin output for :code:`WannaCry`::

	"Plugins": {
		"compilers": {
		    "level": 1, 
		    "plugin_output": {
		        "info_0": "Microsoft Visual C++ 6.0 - 8.0", 
		        "info_1": "Microsoft Visual C++", 
		        "info_2": "Microsoft Visual C++ v6.0", 
		        "info_3": "Microsoft Visual C++ v5.0/v6.0 (MFC)"
		    }, 
		    "summary": "Matching compiler(s):"
		}, 
		"strings": {
		    "level": 2, 
		    "plugin_output": {
		        "Miscellaneous malware strings": [
		            "cmd.exe"
		        ]
		    }, 
		    "summary": "Strings found in the binary may indicate undesirable behavior:"
		}, 
		"findcrypt": {
		    "level": 1, 
		    "plugin_output": {
		        "info_0": "Uses constants related to CRC32", 
		        "info_1": "Uses constants related to AES", 
		        "info_2": "Microsoft's Cryptography API"
		    }, 
		    "summary": "Cryptographic algorithms detected in the binary:"
		}, 
		"btcaddress": {
		    "level": 3, 
		    "plugin_output": {
		        "Contains a valid Bitcoin address": [
		            "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn", 
		            "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw", 
		            "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94"
		        ]
		    }, 
		    "summary": "This program may be a ransomware."
		}, 
		"imports": {
		    "level": 2, 
		    "plugin_output": {
		        "Possibly launches other programs": [
		            "CreateProcessA"
		        ], 
		        "Uses Microsoft's cryptographic API": [
		            "CryptReleaseContext"
		        ],
		        "Interacts with services": [
		            "CreateServiceA", 
		            "OpenServiceA", 
		            "OpenSCManagerA"
		        ]
		        // ...
		    }, 
		    "summary": "The PE contains functions most legitimate programs don't use."
		}, 
		"resources": {
		    "level": 2, 
		    "plugin_output": {
		        "info_0": "Resources amount for 98.1255% of the executable."
		    }, 
		    "summary": "The PE is possibly a dropper."
		}, 
		"mitigation": {
		    "level": 1, 
		    "plugin_output": {
		        "Stack Canary": "disabled", 
		        "SafeSEH": "disabled", 
		        "ASLR": "disabled", 
		        "DEP": "disabled"
		    }, 
		    "summary": "The following exploit mitigation techniques have been detected"
		}, 
		"virustotal": {
		    "level": 3, 
		    "plugin_output": {
		        "Bkav": "W32.WanaCryptBTTc.Worm", 
		        "MicroWorld-eScan": "Trojan.Ransom.WannaCryptor.A", 
		        "nProtect": "Ransom/W32.WannaCry.Zen", 
		        "Paloalto": "generic.ml", 
		        "ClamAV": "Win.Trojan.Agent-6312832-0", 
		        "Kaspersky": "Trojan-Ransom.Win32.Wanna.zbu", 
		        "BitDefender": "Trojan.Ransom.WannaCryptor.A",
		        // ...
		    }, 
		    "summary": "VirusTotal score: 58/62 (Scanned on 2017-07-08 14:55:28)"
		}
	}

`Source <https://manalyzer.org/json/84c82835a5d21bbcf75a61706d8ab549>`_

Additional JSON samples:
------------------------

If you need additional JSON documents to test your Manalyze integration, head to `Manalyzer <https://manalyzer.org>`_ and find a report that interests you. Just change the URL from::

    https://manalyzer.org/report/[md5]

...to...

.. code::

    https://manalyzer.org/json/[md5]

...and you'll be presented with the source JSON document.
