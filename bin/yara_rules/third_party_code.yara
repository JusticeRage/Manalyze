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

rule Mimikatz
{
	meta:
		description = "Contains code from Mimikatz"
		author = "Ivan Kwiatkowski (@JusticeRage)"
		show_strings = "false"
	strings:
		$x64_W2K3_SecData =    { 48 8d 6e 30 48 8d 0d }
		$x64_W2K8_SecData =    { 48 8d 94 24 b0 00 00 00 48 8d 0d }
		$x64_W2K12_SecData =   { 4c 8d 85 30 01 00 00 48 8d 15 }
		$x64_W2K12R2_SecData = { 0f b6 4c 24 30 85 c0 0f 45 cf 8a c1 }
		$x64_WI52_SysCred =    { b9 14 00 00 00 f3 aa 48 8d 3d }
		$x64_WI60_SysCred =    { 48 8b ca f3 aa 48 8d 3d }
		$x64_WI61_SysCred =    { 8b ca f3 aa 48 8d 3d }
		$x86_W2K3_SecData =    { 53 56 8d 45 98 50 b9 }
		$x86_W2K8_SecData =    { 8b 45 14 83 c0 18 50 b9 }
		$x86_WI51_SysCred =    { 00 ab 33 c0 bf }
		$x86_WI52_SysCred =    { 59 33 d2 88 10 40 49 75 }
		$x86_WI60_SysCred =    { 6a 14 59 b8 }
		$x86_WI62_SysCred =    { 6a 14 5a 8b f2 b9 }
		$x86_WI63_SysCred =    { 6a 14 59 8b d1 b8 }
	condition:
		all of ($x64_*) or all of ($x86_*)
}

rule Mimikatz_2
{
	meta:
		description = "Contains strings from Mimikatz"
		author = "Ivan Kwiatkowski (@JusticeRage)"
	strings:
		$primary = "Primary" fullword
		$credentialkeys = "CredentialKeys" fullword
		$bcrypt1 = "BCryptCloseAlgorithmProvider" fullword
		$bcrypt2 = "BCryptDestroyKey" fullword
		$bcrypt3 = "BCryptDecrypt" fullword
		$bcrypt4 = "BCryptEncrypt" fullword
		$bcrypt5 = "BCryptGenerateSymmetricKey" fullword
		$bcrypt6 = "BCryptGetProperty" fullword
		$bcrypt7 = "BCryptSetProperty" fullword
		$bcrypt8 = "BCryptOpenAlgorithmProvider" fullword
	condition:
		$primary and $credentialkeys and 5 of ($bcrypt*)
}

rule Tor
{
	meta:
		description = "Contains strings from Tor"
		author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $tor_1 = "Your server (%s:%d) has not managed to confirm that its DirPort is reachable." ascii
        $tor_2 = "rotate_onion_key" ascii
        $tor_3 = "success: handed off onionskin." ascii
        $tor_4 = "circuit in create_wait. Closing." ascii
        $tor_5 = "x->magic == OR_CIRCUIT_MAGIC" ascii
        $tor_6 = "OR_HSSI_ESTABLISHED" ascii
        $tor_7 = "Acting as intro point" ascii
        $tor_8 = "Hidden service client" ascii
        $tor_9 = "tor-hs-ntor-curve25519-sha3-256-1" ascii
    condition:
        2 of them
}

rule Tor_2
{
    meta:
        description = "Contains cryptographic code taken from Tor"
		author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        // From lib/crypt_ops/crypto_curve25519.c        
        $curve25519_alicesk = { 77 07 6d 0a 73 18 a5 7d 3c 16 c1 72 51 b2 66 45 df 4c 2f 87 eb c0 99 2a b1 77 fb a5 1d b9 2c 2a }
        $curve25519_alicepk = { 85 20 f0 09 89 30 a7 54 74 8b 7d dc b4 3e f7 5a 0d bf 3a 0d 26 38 1a f4 eb a4 a9 8e aa 9b 4e 6a }
        // From lib/crypt_ops/crypto_ed25519.c
        $ed25519_alicesk =  { c5 aa 8d f4 3f 9f 83 7b ed b7 44 2f 31 dc b7 b1 66 d3 85 35 07 6f 09 4b 85 ce 3a 2e 0b 44 58 f7 }
        $ed25519_alicepk =  { fc 51 cd 8e 62 18 a1 a3 8d a4 7e d0 02 30 f0 58 08 16 ed 13 ba 33 03 ac 5d eb 91 15 48 90 80 25 }
        $ed25519_alicesig = { 62 91 d6 57 de ec 24 02 48 27 e6 9c 3a be 01 a3 0c e5 48 a2 84 74 3a 44 5e 36 80 d7 db 5a c3 ac 
                              18 ff 9b 53 8d 16 f2 90 ae 67 f7 60 98 4d c6 59 4a 7c 15 e9 71 6e d2 8d c0 27 be ce ea 1e c4 0a }
    condition:
        all of ($curve25519_*) or all of ($ed25519_*)
}

rule OpenSSL
{
    meta:
        description = "Contains code taken from OpenSSL"
		author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $cryptograms = "CRYPTOGAMS by <appro@openssl.org>"
    condition:
        #cryptograms >= 5
}

rule Libcurl
{
    meta:
        description = "Contains code taken from cURL"
		author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $libcurl = /libcurl\/[0-9.]+/
        $error = "# Fatal libcurl error"
        $a1 = "User-Agent: %s"
        $a2 = "Content-Range: bytes %s%lld/%lld"
        $a3 = "<no protocol>"
        $a4 = "Expect: 100-continue"
        $a5 = "Content-Length: %I64d"
    condition:
        $libcurl or $error or 3 of ($a*)
}

rule WolfSSL
{
    meta:
        author = "@stvemillertime"
        description = "Contains code from WolfSSL"
    strings:
        $base = "CLNTSRVRclient finished" ascii wide
        $base2 = "CLNTserver finished" ascii wide
        $a1 = "server finished" ascii wide
        $a2 = "master secret" ascii wide
        $a3 = "key expansion" ascii wide
        $z1 = "SSLeay wolfSSL compatibility"
        $z2 = "CyaSSL_write lenSend error!"
        $z3 = "CyaSSL_write sendData error!"
        $z4 = "CyaSSL_read lenRecv error!"
        $z5 = "CyaSSL_read data error!"
    condition:
        any of ($base*) and ((any of ($a*)) or (any of ($z*)))
}

rule wsdlpull
{
    meta:
        author = "Ivan Kwiatkowski (@JusticeRage)"
        description = "Contains code from wsdlpull"
        url = "http://wsdlpull.sourceforge.net/"
    strings:
        $multipart = "Content-Type: multipart/form-data; boundary=--MULTI-PARTS-FORM-DATA-BOUNDARY\x0d\x0a" ascii
        $error_1 = "additional header failed..." ascii
        $error_2 = "add cookie failed..." ascii
        $error_3 = "handle not opened..." ascii
        $error_4 = "request failed..." ascii
    condition:
        $multipart or any of ($error_*)
}

rule jsoncpp
{
    meta:
        description = "Contains code from jsoncpp"
        author = "Ivan Kwiatkowski (@JusticeRage)"
        url = "https://github.com/open-source-parsers/jsoncpp/"
    strings:
        $error_1 = "in Json::Value::duplicateStringValue(): Failed to allocate string value buffer" ascii
        $error_2 = "in Json::Value::duplicateAndPrefixStringValue(): Failed to allocate string value buffer" ascii
        $error_3 = "additional six characters expected to parse unicode surrogate pair." ascii
        $error_4 = "in Json::Value::setComment(): Comments must start with /" ascii
        $error_5 = "A valid JSON document must be either an array or an object value." ascii
        $rtti_1 = ".?AVStyledWriter@Json@@" ascii
        $rtti_2 = ".?AVException@Json@@" ascii
        $rtti_3 = ".?AVRuntimeError@Json@@" ascii
    condition:
        all of ($rtti_*) or any of ($error_*)
}
