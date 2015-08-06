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
        author = "JusticeRage"
    strings:
        $adobe = "adobe" nocase wide ascii
        $ms = "microsoft" nocase wide ascii
        $google = "google" nocase wide ascii
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
