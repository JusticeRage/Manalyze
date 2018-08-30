*********************
Initial configuration
*********************

You have just downloaded Manalyze, and while it runs on your system, there are just a few more steps to follow before you can use it fully. Some of the plugins bundled with the program need to be configured manually. In most cases, all you have to do is look at ``bin/manalyze.conf`` and see if there are any values which need editing.

VirusTotal plugin
=================

When you use this plugin for the first time, you're likely to encounter the following error::

    [*] Warning: The VirusTotal API key was not found in the configuration file.
	
In order to submit hashes to VirusTotal, it is necessary to `register <https://www.virustotal.com/en/>`_ on their website and retrieve an API key. If you really can't be bothered, many of these can be found on `GitHub <https://github.com/search?q=%22https%3A%2F%2Fwww.virustotal.com%2Fvtapi%2Fv2%22&type=Code&utf8=%E2%9C%93>`_.

VirusTotal offers two types of API access: public and private. Right now, Manalyze doesn't support any of the "private" features, but if you're lucky enough to have a such a key, at least you won't be bound by the request rate limit. After you have obtained an API key, edit ``bin/manalyze.conf`` and add the following line::

    virustotal.api_key = [your key here]
	
After this, the plugin will be able to retrieve hashes from VirusTotal.

ClamAV plugin
=============

Manalyze can apply ClamAV signatures to detect known malware. Those signature are however **not** distributed with the application because of their size, and the fact that they are constantly updated. This is the reason why running the ClamAV plugin for the first time is likely to print the following error::

    [!] Error: Could not load yara rules (ERROR_COULD_NOT_OPEN_FILE).
    [!] Error: ClamAV rules haven't been generated yet!
    [!] Error: Please run yara_rules/update_clamav_signatures.py to create them, and refer to the documentation for additional information.

You've been promised "additional information": here it is! ClamAV signatures have to be downloaded from the `official website <http://www.clamav.net/>`_. But Manalyze can't read ClamAV signatures out of the box, they first need to be converted to Yara rules. The whole process was a little cumbersome, so a Python script was written to automate the process. Simply run::

    python yara_rules/update_clamav_signatures.py
	
...and the rules will be added to Manalyze. Run the script anytime you want to update the signatures!

Additional considerations
-------------------------

ClamAV signatures are divided into two files, the "main" and the "daily" signatures. The former isn't updated very often, as opposed to the latter. For this reason, the python script will not download the "main" signatures if they have already been retreived: only the daily rules will be regenerated. To perform a full upgrade, call the script with the following parameter::

    python yara_rules/update_clamav_signatures.py --main
