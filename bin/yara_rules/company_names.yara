/*
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Manalyze is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
*/

rule CompanyNames
{
    meta:
        description = "Contains the names of famous IT companies"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
		// Not checking for Microsoft, because many MS binaries are verified through the 
		// security catalog and do not embed a digital signature.
		$adobe = "adobe" nocase wide ascii
        $google = "google" nocase wide ascii
		$firefox = "firefox" nocase wide ascii
        $intel = "intel" nocase wide ascii
        $amd = "advanced micro devices" nocase wide ascii
        $amd2 = "amd" nocase wide ascii fullword
        $oracle = "oracle" nocase wide ascii
        $sun = "sun microsystems" nocase wide ascii
        $nvidia = "nvidia" nocase wide ascii
        $ati = "ati technologies" nocase wide ascii
        $ati2 = "ati" nocase wide ascii fullword
        $epson = "epson" nocase wide ascii fullword
        $canon = "canon" nocase wide ascii fullword
        $qualcomm = "qualcomm" nocase wide ascii
        $broadcom = "broadcom" nocase wide ascii
        $realtek = "realtek" nocase wide ascii
        $hp = /hewlett[ -]packard/ nocase wide ascii
        $motorola = "motorola" nocase wide ascii
        $kas = "kaspersky" nocase wide ascii
        $mcafee = "mcafee" nocase wide ascii
    condition:
        any of them
}

rule CompanyNamesHomographs
{
    meta:
        description = "Tries to impersonate a famous IT company with homographs"
        author = "Ivan Kwiatkowski (@JusticeRage)"
		type = "homograph"
    strings:
		$adobe = "adobe" nocase wide ascii
		$adobe_homograph = { (41 00 | 10 04 | 91 03 | 21 FF) (64 00 | 01 05 | 7E 21 | 44 FF) (6F 00 | BF 03 | 3E 04 | 4F FF) (62 00 | 2C 04 | 42 FF) (65 00 | 35 04 | 45 FF) }
		$microsoft = "microsoft" nocase wide ascii
		$microsoft_homograph = { (4D 00 | 9C 03 | 1C 04 | 6F 21 | 2D FF) (69 00 | 56 04 | 70 21 | 49 FF) (63 00 | F2 03 | 41 04 | 7D 21 | 43 FF) (72 00 | 52 FF) (6F 00 | BF 03 | 3E 04 | 4F FF) (73 00 | 55 04 | 53 FF) (6F 00 | BF 03 | 3E 04 | 4F FF) (66 00 | 46 FF) (74 00 | 54 FF) }
		$google = "google" nocase wide ascii
		$google_homograph = { (47 00 | 0C 05 | 27 FF) (6F 00 | BF 03 | 3E 04 | 4F FF) (6F 00 | BF 03 | 3E 04 | 4F FF) (67 00 | 47 FF) (6C 00 | 7C 21 | 4C FF) (65 00 | 35 04 | 45 FF) }
	condition:
		// Do not match on the original strings, as that will have been caught above.
		($adobe_homograph and not $adobe) or 
		($google_homograph and not $google) or 
		($microsoft_homograph and not $microsoft)
}
