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
import "manape"

rule Domains_URLs
{
    meta:
        description = "Contains domain names"
        author = "Sergey Mineev"
    strings:
        $domain1 = /www\.[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/
        $domain2 = /[a-zA-Z0-9\-\.]{5,}\.(com|org|net|de|uk|fr|ru|info|top|xyz|tk|cn|br|jp|it|ir|nl|ca|au|es|ch|gov|edu|se|us)/ nocase fullword
        $domain3 = /(https?|ftp):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-]*[\w\-])?/
        $domain4 = /(ht|f)tps?\:\/\/[a-zA-Z0-9\-\._]+(\.[a-zA-Z0-9\-\._]+){2,}(\/?)([a-zA-Z0-9\-\.\?\,\'\/\\\+&%\$#_]*)/
        $domain5 = /https?\:\/\/www.[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}/ fullword
        $domain6 = /[a-zA-Z0-9\-\.]+\.[a-zA-Z0-9\-\.]{5,}\.((com|org|net|de|uk|fr|ru|info|top|xyz|tk|cn|br|jp|it|ir|nl|ca|au|es|ch|gov|edu|se|us))/ fullword nocase
        $domain7 = /[a-zA-Z0-9\-\.]+\.[a-zA-Z0-9\-\.]+\.[a-zA-Z0-9\-\.]{5,}\.(com|org|net|de|uk|fr|ru|info|top|xyz|tk|cn|br|jp|it|ir|nl|ca|au|es|ch|gov|edu|se|us)/ fullword nocase
    condition:
		// Calling C++ code in Manalyze takes care of filtering results in the authenticode signature or RT_MANIFEST resource.
		// This is needed because Yara reports all matching strings if the condition evaluates to "true", even if some of the strings
		// are located in a zone excluded in the condition.
		any of them
}