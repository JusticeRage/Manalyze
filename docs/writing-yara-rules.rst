******************
Writing Yara rules
******************

This section is dedicated to the intricacies of writing Yara rules which can be used by Manalyze.

Introduction
============

Because Manalyze already includes an (hopefully) efficient PE parser, it was deemed unnecessary to rely on the one that is provided with Yara. The Yara engine provided with Manalyze was essentially stripped down to the library code and contains none of the plugins provided with the original distribution. Custom C++ wrappers were also added to the project. All the modifications to the code may be found on `GitHub <https://github.com/JusticeRage/yara>`_.

For this reason, Yara rules relying on the original PE module will not work with Manalyze ; they need to be modified so they rely on the one provided to Yara by the tool.

.. note:: The functionnalities provided by this module are added on a need basis. If you need additional data exposed, please create `an issue <https://github.com/JusticeRage/Manalyze/issues>`_ on GitHub!

Supported commands
==================

All scripts relying on Manalyze's PE module must start by importing it with the ``import "manape"`` directive.

* The entry point of the executable is designated by ``manape.ep``.
* The number of sections is exposed through ``manape.num_sections``.
* For each section, you can access the start address and the size with ``manape.section[i].start`` and ``manape.section[i].size``, ``i`` being the zero-based index of the section.
* You can scan the ``VERSION_INFO`` resource with ``manape.version_info.start`` and ``manape.version_info.size``.
* The authenticode signature of the binary can be located through ``manape.authenticode.start`` and ``manape.authenticode.size``.

Sample rule
===========

::

	import "manape"

	rule D_Win_dot_Trojan_dot_Patched_dash_300
	{
		meta:
			signature = "Win.Trojan.Patched-300"
		strings:
			$a0 = { 837c24080175 }
			$a1 = { 726f6341c745e064647265 }
			$a2 = { 43006f006d00700061006e0079004e0061006d006500000000004d006900630072006f0073006f0066007400200043006f00720070006f007200610074006900 }
		condition:
			$a0 at manape.ep and $a1 and $a2 in (manape.version_info.start .. manape.version_info.start + manape.version_info.size)
	}