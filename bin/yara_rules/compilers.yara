import "manape"

rule MinGW_v3_2_x__Dll_main_
{
meta:
    description = "MinGW v3.2.x (Dll_main)"
strings:
    	$a0 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 96 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 }
	$a1 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 96 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 00 00 EB EB 8D B4 26 00 00 00 00 85 C0 75 D0 E8 47 00 00 00 EB C9 90 8D 74 26 00 C7 04 24 80 00 00 00 E8 F4 05 00 00 A3 00 30 00 10 85 C0 74 1A C7 00 00 00 00 00 A3 10 30 00 10 E8 3B 02 00 00 E8 C6 01 00 00 E9 75 FF FF FF E8 BC 05 00 00 C7 00 0C 00 00 00 31 C0 EB 98 89 F6 55 89 E5 83 EC 08 89 5D FC 8B 15 00 30 00 10 85 D2 74 29 8B 1D 10 30 00 10 83 EB 04 39 D3 72 0D 8B 03 85 C0 75 2A 83 EB 04 39 D3 73 F3 89 14 24 E8 6B 05 00 00 31 C0 A3 00 30 00 10 C7 04 24 00 00 00 00 E8 48 05 00 00 8B 5D FC 89 EC 5D C3 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Microsoft_Visual_C______
{
meta:
    description = "Microsoft Visual C++ ?.?"
strings:
    	$a0 = { 83 ?? ?? 6A 00 FF 15 F8 10 0B B0 8D ?? ?? ?? 51 6A 08 6A 00 6A 00 68 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_C____1990_1992_
{
meta:
    description = "Microsoft C++ (1990/1992)"
strings:
    	$a0 = { B8 00 30 CD 21 3C 03 73 ?? 0E 1F BA ?? ?? B4 09 CD 21 06 33 C0 50 CB }

condition:
    	$a0 at manape.ep
}

    
rule WATCOM_C_C__
{
meta:
    description = "WATCOM C/C++"
strings:
    	$a0 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_CAB_SFX
{
meta:
    description = "Microsoft CAB SFX"
strings:
    	$a0 = { E8 0A 00 00 00 E9 7A FF FF FF CC CC CC CC CC }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C___4_2
{
meta:
    description = "Microsoft Visual C++ 4.2"
strings:
    	$a0 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 }

condition:
    	$a0 at manape.ep
}

    
rule MS_Run_Time_Library_1990__10_
{
meta:
    description = "MS Run-Time Library 1990 (10)"
strings:
    	$a0 = { E8 ?? ?? 2E FF 2E ?? ?? BB ?? ?? E8 ?? ?? CB }

condition:
    	$a0 at manape.ep
}

    
rule MinGW_v3_2_x__Dll_mainCRTStartup_
{
meta:
    description = "MinGW v3.2.x (Dll_mainCRTStartup)"
strings:
    	$a0 = { 55 89 E5 83 EC 08 6A 00 6A 00 6A 00 6A 00 E8 0D 00 00 00 B8 00 00 00 00 C9 C3 90 90 90 90 90 90 FF 25 38 20 00 10 90 90 00 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00 FF FF FF FF 00 00 00 00 00 }

condition:
    	$a0 at manape.ep
}

    
rule LCC_Win32_DLL
{
meta:
    description = "LCC Win32 DLL"
strings:
    	$a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 ?? ?? ?? FF 75 10 FF 75 0C FF 75 08 A1 }

condition:
    	$a0 at manape.ep
}

    
rule Nullsoft_Install_System_v2_0
{
meta:
    description = "Nullsoft Install System v2.0"
strings:
    	$a0 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }
	$a1 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 68 68 92 40 00 56 FF D5 E8 6A FF FF FF 85 C0 0F 84 57 01 00 00 BE 20 E4 42 00 56 FF 15 68 70 40 00 68 5C 92 40 00 56 E8 9C 28 00 00 57 FF 15 BC 70 40 00 BE 00 40 43 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 40 43 00 22 A3 20 EC 42 00 75 0A C6 44 24 14 22 BE 01 40 43 00 FF 74 24 14 56 E8 8A 23 00 00 50 FF 15 80 71 40 00 8B F8 89 7C 24 18 EB 61 80 F9 20 75 06 40 80 38 20 74 FA 80 38 22 C6 44 24 14 20 75 06 40 C6 44 24 14 22 80 38 2F 75 31 40 80 38 53 75 0E 8A 48 01 80 C9 20 80 F9 20 75 03 }

condition:
    	$a0 or $a1
}

    
rule Turbo_C_1987_or_Borland_C___1991
{
meta:
    description = "Turbo C 1987 or Borland C++ 1991"
strings:
    	$a0 = { FB BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21 }

condition:
    	$a0 at manape.ep
}

    
rule Borland_Delphi_v6_0___v7_0
{
meta:
    description = "Borland Delphi v6.0 - v7.0"
strings:
    	$a0 = { 53 8B D8 33 C0 A3 0? ?? ?? ?0 6A 00 E8 0? ?? ?0 FF A3 0? ?? ?? ?0 A1 0? ?? ?? ?0 A3 0? ?? ?? ?0 33 C0 A3 0? ?? ?? ?0 33 C0 A3 0? ?? ?? ?0 E8 }
	$a1 = { BA ?? ?? ?? ?? 83 7D 0C 01 75 ?? 50 52 C6 05 ?? ?? ?? ?? ?? 8B 4D 08 89 0D ?? ?? ?? ?? 89 4A 04 }
	$a2 = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 }
	$a3 = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? FB FF A1 ?? ?? ?? ?? 8B ?? E8 ?? ?? FF FF 8B 0D ?? ?? ?? ?? A1 ?? ?? ?? ?? 8B 00 8B 15 ?? ?? ?? ?? E8 ?? ?? FF FF A1 ?? ?? ?? ?? 8B ?? E8 ?? ?? FF FF E8 ?? ?? FB FF 8D 40 }
	$a4 = { 53 8B D8 33 C0 A3 00 ?? ?? ?? 06 A0 0E 80 ?? ?? 0F FA 30 ?? ?? ?? 0A 10 ?? ?? ?? 0A 30 ?? ?? ?? 03 3C 0A 30 ?? ?? ?? 03 3C 0A 30 ?? ?? ?? E8 }

condition:
    	$a0 or $a1 at manape.ep or $a2 or $a3 at manape.ep or $a4 at manape.ep
}

    
rule Microsoft_Visual_C___7_0
{
meta:
    description = "Microsoft Visual C++ 7.0"
strings:
    	$a0 = { 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 40 89 45 E4 8B 75 0C }
	$a1 = { 6A 18 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 94 00 00 00 8B C7 E8 ?? ?? ?? ?? 89 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Microsoft_Visual_C___7_1
{
meta:
    description = "Microsoft Visual C++ 7.1"
strings:
    	$a0 = { 8B FF 55 8B EC 56 33 F6 39 75 0C 0F 84 ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 39 75 0C 0F 84 ?? ?? ?? ?? 33 C0 40 5E 5D C2 0C 00 }
	$a1 = { 8B FF 55 8B EC 56 33 F6 39 75 0C 0F 84 ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 68 80 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 59 A3 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 89 30 A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 }
	$a2 = { 8B FF 55 8B EC 56 33 F6 39 75 0C 0F 84 ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 68 80 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 59 A3 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 89 30 A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? FF 05 ?? ?? ?? ?? 59 59 33 C0 40 5E 5D C2 0C 00 }
	$a3 = { 8B FF 55 8B EC 56 33 F6 39 75 0C 75 0E 39 35 ?? ?? ?? ?? 7E 2D FF 0D ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 75 3D 68 80 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 59 A3 ?? ?? ?? ?? 75 04 33 C0 EB 67 89 30 A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 }
	$a4 = { 8B FF 55 8B EC 56 33 F6 39 75 0C 0F 84 ?? ?? ?? ?? 83 7D 0C 01 A1 ?? ?? ?? ?? 8B 00 A3 ?? ?? ?? ?? 75 44 68 80 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 59 A3 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 89 30 A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 }
	$a5 = { 55 8B EC 83 EC 08 53 56 57 55 FC 8B 5D 0C 8B 45 08 F7 40 04 06 00 00 00 0F 85 AB 00 00 00 89 45 F8 8B 45 10 89 45 FC 8D 45 F8 89 43 FC 8B 73 0C 8B 7B 08 53 E8 ?? ?? ?? ?? 83 C4 04 0B C0 74 7B 83 FE FF 74 7D 8D 0C 76 8B 44 8F 04 0B C0 74 59 56 55 }

condition:
    	$a0 or $a1 or $a2 or $a3 or $a4 or $a5
}

    
rule WATCOM_C_C___DLL
{
meta:
    description = "WATCOM C/C++ DLL"
strings:
    	$a0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 }

condition:
    	$a0 at manape.ep
}

    
rule Zortech_C
{
meta:
    description = "Zortech C"
strings:
    	$a0 = { E8 ?? ?? 2E FF ?? ?? ?? FC 06 }

condition:
    	$a0 at manape.ep
}

    
rule Watcom_C_C__
{
meta:
    description = "Watcom C/C++"
strings:
    	$a0 = { E9 ?? ?? 00 00 03 10 40 00 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 69 6D 65 20 73 79 73 74 65 6D 2E 20 28 63 29 20 43 6F 70 79 72 69 67 68 74 20 62 79 20 57 41 54 43 4F 4D 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 43 6F 72 70 2E 20 }
	$a1 = { E9 ?? ?? 00 00 03 10 40 00 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 69 6D 65 20 73 79 73 74 65 6D 2E 20 28 63 29 20 43 6F 70 79 72 69 67 68 74 20 62 79 20 57 41 54 43 4F 4D 20 49 6E 74 65 72 6E 61 74 69 6F 6E 61 6C 20 43 6F 72 70 2E 20 31 39 38 38 2D 31 39 39 35 2E 20 41 6C 6C 20 72 69 67 68 74 73 20 72 65 73 65 72 76 65 64 2E 00 00 00 00 00 00 }

condition:
    	$a0 or $a1
}

    
rule Borland_Delphi_Setup_Module
{
meta:
    description = "Borland Delphi Setup Module"
strings:
    	$a0 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 }

condition:
    	$a0 at manape.ep
}

    
rule InstallAnywhere_6_1___Zero_G_Software_Inc
{
meta:
    description = "InstallAnywhere 6.1 ->Zero G Software Inc"
strings:
    	$a0 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_Basic_5_0
{
meta:
    description = "Microsoft Visual Basic 5.0"
strings:
    	$a0 = { FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 }

condition:
    	$a0
}

    
rule Nullsoft_Install_System_v1_xx
{
meta:
    description = "Nullsoft Install System v1.xx"
strings:
    	$a0 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 0B 56 FF D7 8B F0 8A 06 84 C0 75 F1 80 3E 00 74 05 56 FF D7 8B F0 89 74 24 14 80 3E 20 75 07 56 FF D7 8B F0 EB F4 80 3E 2F 75 }
	$a1 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 }
	$a2 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 }
	$a3 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 56 56 56 89 75 E4 E8 C1 C9 FF FF 8B 1D 68 70 40 00 83 C4 0C 89 45 E8 89 75 F0 6A 02 56 6A FC 57 FF D3 89 45 FC 8D 45 F8 56 50 8D 45 E4 6A 04 50 57 FF 15 48 70 40 00 85 C0 75 07 BB 7C 9E 40 00 EB 7A 56 56 56 57 FF D3 39 75 FC 7E 62 BF 74 A2 40 00 B8 00 10 00 00 39 45 FC 7F 03 8B 45 FC 8D 4D F8 56 51 50 57 FF 75 EC FF 15 48 70 40 00 85 C0 74 5A FF 75 F8 57 FF 75 E8 E8 4D C9 FF FF 89 45 E8 8B 45 F8 29 45 FC 83 C4 0C 39 75 F4 75 11 57 E8 D3 F9 FF FF 85 C0 59 74 06 8B 45 F0 89 45 F4 8B 45 F8 01 45 F0 39 75 FC }

condition:
    	$a0 at manape.ep or $a1 at manape.ep or $a2 at manape.ep or $a3 at manape.ep
}

    
rule FreePascal_2_0_0_Win32
{
meta:
    description = "FreePascal 2.0.0 Win32"
strings:
    	$a0 = { C6 05 ?? ?? ?? ?? 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 }
	$a1 = { C6 05 00 80 40 00 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Symantec_Visual_Cafe_v3_0
{
meta:
    description = "Symantec Visual Cafe v3.0"
strings:
    	$a0 = { 64 8B 05 ?? ?? ?? ?? 55 8B EC 6A FF 68 ?? ?? 40 ?? 68 ?? ?? 40 ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 08 50 53 56 57 89 65 E8 C7 45 FC }

condition:
    	$a0 at manape.ep
}

    
rule Borland_Delphi_v2_0
{
meta:
    description = "Borland Delphi v2.0"
strings:
    	$a0 = { E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0A ?? ?? ?? B8 ?? ?? ?? ?? C3 }

condition:
    	$a0 at manape.ep
}

    
rule Nullsoft_Install_System_2_0b4
{
meta:
    description = "Nullsoft Install System 2.0b4"
strings:
    	$a0 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 }
	$a1 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 }

condition:
    	$a0 or $a1
}

    
rule Nullsoft_Install_System_2_06
{
meta:
    description = "Nullsoft Install System 2.06"
strings:
    	$a0 = { 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 ?? ?? ?? ?? C6 44 24 14 20 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 02 23 00 00 BE ?? ?? ?? ?? 56 }

condition:
    	$a0
}

    
rule CreateInstall_Stub_vx_x
{
meta:
    description = "CreateInstall Stub vx.x"
strings:
    	$a0 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F 00 00 33 F6 56 BF 00 30 00 00 FF 15 20 61 40 00 50 FF 15 2C 61 40 00 6A 04 57 68 00 FF 01 00 56 FF 15 CC 60 40 00 6A 04 A3 CC 35 40 00 57 68 00 0F 01 00 56 FF 15 CC 60 40 00 68 00 01 00 00 BE B0 3F 40 00 56 A3 C4 30 40 00 FF 75 08 FF 15 10 61 40 00 }
	$a1 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F 00 00 33 F6 56 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Metrowerks_CodeWarrior__DLL__v2_0
{
meta:
    description = "Metrowerks CodeWarrior (DLL) v2.0"
strings:
    	$a0 = { 55 89 E5 53 56 57 8B 75 0C 8B 5D 10 83 FE 01 74 05 83 FE 02 75 12 53 56 FF 75 08 E8 6E FF FF FF 09 C0 75 04 31 C0 EB 21 53 56 FF 75 08 E8 ?? ?? ?? ?? 89 C7 09 F6 74 05 83 FE 03 75 0A 53 56 FF 75 08 E8 47 FF FF FF 89 F8 8D 65 F4 5F 5E 5B 5D C2 0C 00 C9 }

condition:
    	$a0
}

    
rule Reg2Exe_2_20_2_21___by_Jan_Vorel
{
meta:
    description = "Reg2Exe 2.20/2.21 - by Jan Vorel"
strings:
    	$a0 = { 6A 00 E8 7D 12 00 00 A3 A0 44 40 00 E8 79 12 00 00 6A 0A 50 6A 00 FF 35 A0 44 40 00 E8 0F 00 00 00 50 E8 69 12 00 00 CC CC CC CC CC CC CC CC CC 68 2C 02 00 00 68 00 00 00 00 68 B0 44 40 00 E8 3A 12 00 00 83 C4 0C 8B 44 24 04 A3 B8 44 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 32 12 00 00 A3 B0 44 40 00 68 F4 01 00 00 68 BC 44 40 00 FF 35 B8 44 40 00 E8 1E 12 00 00 B8 BC 44 40 00 89 C1 8A 30 40 80 FE 5C 75 02 89 C1 80 FE 00 75 F1 C6 01 00 E8 EC 18 00 00 E8 28 16 00 00 E8 4A 12 00 00 68 00 FA 00 00 68 08 00 00 00 FF 35 B0 44 40 00 E8 E7 11 00 00 A3 B4 44 40 00 8B 15 D4 46 40 00 E8 65 0A 00 00 BB 00 00 10 00 B8 01 00 00 00 E8 72 0A 00 00 74 09 C7 00 01 00 00 00 83 C0 04 A3 D4 46 40 00 FF 35 B4 44 40 00 E8 26 05 00 00 8D 0D B8 46 40 00 5A E8 CF 0F 00 00 FF 35 B4 44 40 00 FF 35 B8 46 40 00 E8 EE 06 00 00 8D 0D B4 46 40 00 5A E8 }
	$a1 = { 6A 00 E8 7D 12 00 00 A3 A0 44 40 00 E8 79 12 00 00 6A 0A 50 6A 00 FF 35 A0 44 40 00 E8 0F 00 00 00 50 E8 69 12 00 00 CC CC CC CC CC CC CC CC CC 68 2C 02 00 00 68 00 00 00 00 68 B0 44 40 00 E8 3A 12 00 00 83 C4 0C 8B 44 24 04 A3 B8 44 40 00 68 00 00 00 00 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Reg2Exe_2_24___by_Jan_Vorel
{
meta:
    description = "Reg2Exe 2.24 - by Jan Vorel"
strings:
    	$a0 = { 6A 00 E8 CF 20 00 00 A3 F4 45 40 00 E8 CB 20 00 00 6A 0A 50 6A 00 FF 35 F4 45 40 00 E8 07 00 00 00 50 E8 BB 20 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 F8 45 40 00 E8 06 19 00 00 83 C4 0C 8B 44 24 04 A3 FC 45 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 8C 20 00 00 A3 F8 45 40 00 E8 02 20 00 00 E8 32 1D 00 00 E8 20 19 00 00 E8 A3 16 00 00 68 01 00 00 00 68 38 46 40 00 68 00 00 00 00 8B 15 38 46 40 00 E8 71 4F 00 00 B8 00 00 10 00 BB 01 00 00 00 E8 82 4F 00 00 FF 35 48 41 40 00 B8 00 01 00 00 E8 9D 15 00 00 8D 0D 1C 46 40 00 5A E8 82 16 00 00 68 00 01 00 00 FF 35 1C 46 40 00 E8 24 20 00 00 A3 24 46 40 00 FF 35 48 41 40 00 FF 35 24 46 40 00 FF 35 1C 46 40 00 E8 DC 10 00 00 8D 0D 14 46 40 00 5A E8 4A 16 }
	$a1 = { 6A 00 E8 CF 20 00 00 A3 F4 45 40 00 E8 CB 20 00 00 6A 0A 50 6A 00 FF 35 F4 45 40 00 E8 07 00 00 00 50 E8 BB 20 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 F8 45 40 00 E8 06 19 00 00 83 C4 0C 8B 44 24 04 A3 FC 45 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Free_Pascal_0_99_10
{
meta:
    description = "Free Pascal 0.99.10"
strings:
    	$a0 = { E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29 }

condition:
    	$a0
}

    
rule Microsoft_Visual_C___v4_2
{
meta:
    description = "Microsoft Visual C++ v4.2"
strings:
    	$a0 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 ?? ?? C7 }
	$a1 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 ?? ?? ?? ?? ?? ?? 83 ?? ?? 53 56 57 89 ?? ?? FF }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule CAN2EXE_v0_01
{
meta:
    description = "CAN2EXE v0.01"
strings:
    	$a0 = { 26 8E 06 ?? ?? B9 ?? ?? 33 C0 8B F8 F2 AE E3 ?? 26 38 05 75 ?? EB ?? E9 }

condition:
    	$a0 at manape.ep
}

    
rule Borland_C___for_Win32_1994
{
meta:
    description = "Borland C++ for Win32 1994"
strings:
    	$a0 = { A1 ?? ?? ?? ?? C1 ?? ?? A3 ?? ?? ?? ?? 83 ?? ?? ?? ?? 75 ?? 57 51 33 C0 BF }

condition:
    	$a0 at manape.ep
}

    
rule Borland_C___for_Win32_1995
{
meta:
    description = "Borland C++ for Win32 1995"
strings:
    	$a0 = { A1 ?? ?? ?? ?? C1 ?? ?? A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 }

condition:
    	$a0 at manape.ep
}

    
rule MinGW_v3_2_x__Dll_WinMain_
{
meta:
    description = "MinGW v3.2.x (Dll_WinMain)"
strings:
    	$a0 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 76 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 }
	$a1 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 76 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 00 00 EB EB 8D B4 26 00 00 00 00 85 C0 75 D0 E8 47 00 00 00 EB C9 90 8D 74 26 00 C7 04 24 80 00 00 00 E8 A4 05 00 00 A3 00 30 00 10 85 C0 74 1A C7 00 00 00 00 00 A3 10 30 00 10 E8 1B 02 00 00 E8 A6 01 00 00 E9 75 FF FF FF E8 6C 05 00 00 C7 00 0C 00 00 00 31 C0 EB 98 89 F6 55 89 E5 83 EC 08 89 5D FC 8B 15 00 30 00 10 85 D2 74 29 8B 1D 10 30 00 10 83 EB 04 39 D3 72 0D 8B 03 85 C0 75 2A 83 EB 04 39 D3 73 F3 89 14 24 E8 1B 05 00 00 31 C0 A3 00 30 00 10 C7 04 24 00 00 00 00 E8 F8 04 00 00 8B 5D FC 89 EC 5D C3 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Microsoft_Visual_C___V8_0
{
meta:
    description = "Microsoft Visual C++ V8.0"
strings:
    	$a0 = { 6A 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 94 00 00 00 53 6A 00 8B ?? ?? ?? ?? ?? FF D7 50 FF ?? ?? ?? ?? ?? 8B F0 85 F6 75 0A 6A 12 E8 ?? ?? ?? ?? 59 EB 18 89 1E 56 FF ?? ?? ?? ?? ?? 56 85 C0 75 14 50 FF D7 50 FF ?? ?? ?? ?? ?? B8 }

condition:
    	$a0 at manape.ep
}

    
rule MingWin32_v_____h_
{
meta:
    description = "MingWin32 v?.? (h)"
strings:
    	$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? 00 E8 ?? FE FF FF 90 8D B4 26 00 00 00 00 55 }

condition:
    	$a0 at manape.ep
}

    
rule ExeTools_COM2EXE
{
meta:
    description = "ExeTools COM2EXE"
strings:
    	$a0 = { E8 ?? ?? 5D 83 ED ?? 8C DA 2E 89 96 ?? ?? 83 C2 ?? 8E DA 8E C2 2E 01 96 ?? ?? 60 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_CAB_SFX_module
{
meta:
    description = "Microsoft CAB SFX module"
strings:
    	$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? 10 00 01 8B F0 8A 06 3C 22 75 14 8A 46 01 46 84 C0 74 04 3C 22 75 F4 80 3E 22 75 0D ?? EB 0A 3C 20 }

condition:
    	$a0 at manape.ep
}

    
rule FreePascal_1_0_4_Win32_DLL_____Berczi_Gabor__Pierre_Muller___Peter_Vreman_
{
meta:
    description = "FreePascal 1.0.4 Win32 DLL -> (Berczi Gabor, Pierre Muller & Peter Vreman)"
strings:
    	$a0 = { C6 05 ?? ?? ?? ?? 00 55 89 E5 53 56 57 8B 7D 08 89 3D ?? ?? ?? ?? 8B 7D 0C 89 3D ?? ?? ?? ?? 8B 7D 10 89 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 5F 5E 5B 5D C2 0C 00 }

condition:
    	$a0
}

    
rule Silicon_Realms_Install_Stub
{
meta:
    description = "Silicon Realms Install Stub"
strings:
    	$a0 = { 55 8B EC 6A FF 68 ?? 92 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? ?? 40 00 33 D2 8A D4 89 15 ?? ?? 40 00 8B C8 81 E1 FF 00 00 00 89 0D ?? ?? 40 00 C1 E1 08 03 CA 89 0D ?? ?? 40 00 C1 E8 10 A3 }
	$a1 = { 55 8B EC 6A FF 68 ?? 92 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? ?? 40 00 33 D2 8A D4 89 15 ?? ?? 40 00 8B C8 81 E1 FF 00 00 00 89 0D ?? ?? 40 00 C1 E1 08 03 CA 89 0D ?? ?? 40 00 C1 E8 10 A3 ?? ?? 40 00 33 F6 56 E8 ?? ?? 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 ?? ?? 00 00 FF 15 ?? 91 40 00 A3 ?? ?? 40 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 ?? ?? FF FF 89 75 D0 8D 45 A4 50 FF 15 ?? 91 40 00 E8 ?? ?? 00 00 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50 FF 75 9C 56 56 FF 15 ?? 91 40 00 50 E8 ?? ?? FF FF 89 45 A0 50 E8 ?? ?? FF FF 8B 45 EC 8B 08 8B 09 89 4D 98 50 51 E8 ?? ?? 00 00 59 59 C3 8B 65 E8 FF 75 98 E8 ?? ?? FF FF 83 3D ?? ?? 40 00 01 75 05 }

condition:
    	$a0 or $a1
}

    
rule Setup_Factory_6_x_Custom
{
meta:
    description = "Setup Factory 6.x Custom"
strings:
    	$a0 = { 55 8B EC 6A FF 68 ?? 61 40 00 68 ?? 43 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? 61 40 00 33 D2 8A D4 89 15 A0 A9 40 00 8B C8 81 E1 FF 00 00 00 89 0D }

condition:
    	$a0 at manape.ep
}

    
rule Inno_Setup_Module_v3_0_4_beta_v3_0_6_v3_0_7
{
meta:
    description = "Inno Setup Module v3.0.4-beta/v3.0.6/v3.0.7"
strings:
    	$a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C }

condition:
    	$a0
}

    
rule Microsoft_C__1990_1992_
{
meta:
    description = "Microsoft C (1990/1992)"
strings:
    	$a0 = { B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C___DLL
{
meta:
    description = "Microsoft Visual C++ DLL"
strings:
    	$a0 = { 53 B8 01 00 00 00 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D ?? ?? ?? ?? ?? 75 09 33 C0 }
	$a1 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C }
	$a2 = { 53 56 57 BB 01 ?? ?? ?? 8B ?? 24 14 }
	$a3 = { 53 55 56 8B 74 24 14 85 F6 57 B8 01 00 00 00 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep or $a2 at manape.ep or $a3 at manape.ep
}

    
rule Microsoft_C_for_Windows__2_
{
meta:
    description = "Microsoft C for Windows (2)"
strings:
    	$a0 = { 8C D8 ?? 45 55 8B EC 1E 8E D8 57 56 89 }

condition:
    	$a0 at manape.ep
}

    
rule PowerBASIC_Win_8_00
{
meta:
    description = "PowerBASIC/Win 8.00"
strings:
    	$a0 = { 55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? 40 00 04 00 75 05 E9 14 04 00 00 E9 19 02 }

condition:
    	$a0 at manape.ep
}

    
rule Metrowerks_CodeWarrior_v2_0__Console_
{
meta:
    description = "Metrowerks CodeWarrior v2.0 (Console)"
strings:
    	$a0 = { 55 89 E5 55 B8 FF FF FF FF 50 50 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 }

condition:
    	$a0
}

    
rule Symantec_C_v4_00___Libraries
{
meta:
    description = "Symantec C v4.00 + Libraries"
strings:
    	$a0 = { FA B8 ?? ?? DB E3 8E D8 8C 06 ?? ?? 8B D8 2B 1E ?? ?? 89 1E ?? ?? 26 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C___v6_0_DLL
{
meta:
    description = "Microsoft Visual C++ v6.0 DLL"
strings:
    	$a0 = { 83 7C 24 08 01 75 09 8B 44 24 04 A3 ?? ?? 00 10 E8 8B FF FF FF }
	$a1 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C }
	$a2 = { 55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }
	$a3 = { 55 8D 6C ?? ?? 81 EC ?? ?? ?? ?? 8B 45 ?? 83 F8 01 56 0F 84 ?? ?? ?? ?? 85 C0 0F 84 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep or $a2 or $a3 at manape.ep
}

    
rule MinGW_GCC_3_x
{
meta:
    description = "MinGW GCC 3.x"
strings:
    	$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? ?? ?? E8 ?? ?? FF FF ?? ?? ?? ?? ?? ?? ?? ?? 55 }

condition:
    	$a0 at manape.ep
}

    
rule MS_Run_Time_Library_1992__14_
{
meta:
    description = "MS Run-Time Library 1992 (14)"
strings:
    	$a0 = { 1E 06 8C C8 8E D8 8C C0 A3 ?? ?? 83 C0 ?? A3 ?? ?? B4 30 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_C__1988_1989_
{
meta:
    description = "Microsoft C (1988/1989)"
strings:
    	$a0 = { B4 30 CD 21 3C 02 73 ?? CD 20 BF ?? ?? 8B ?? ?? ?? 2B F7 81 ?? ?? ?? 72 }

condition:
    	$a0 at manape.ep
}

    
rule WATCOM_C_C___32_Run_Time_System_1989__1994
{
meta:
    description = "WATCOM C/C++ 32 Run-Time System 1989, 1994"
strings:
    	$a0 = { 0E 1F 8C C6 B4 ?? 50 BB ?? ?? CD 21 73 ?? 58 CD 21 72 }

condition:
    	$a0 at manape.ep
}

    
rule Setup_Factory_v6_0_0_3_Setup_Launcher
{
meta:
    description = "Setup Factory v6.0.0.3 Setup Launcher"
strings:
    	$a0 = { 55 8B EC 6A FF 68 90 61 40 00 68 70 3B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 14 61 40 00 33 D2 8A D4 89 15 5C 89 40 00 8B C8 81 E1 FF 00 00 00 89 0D 58 89 40 00 C1 E1 08 03 CA 89 0D 54 89 40 00 C1 E8 10 A3 50 89 }
	$a1 = { 55 8B EC 6A FF 68 90 61 40 00 68 70 3B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 14 61 40 00 33 D2 8A D4 89 15 5C 89 40 00 8B C8 81 E1 FF 00 00 00 89 0D 58 89 40 00 C1 E1 08 03 CA 89 0D 54 89 40 00 C1 E8 10 A3 50 89 40 00 33 F6 56 E8 E0 00 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 E6 0F 00 00 FF 15 10 61 40 00 A3 40 8E 40 00 E8 A4 0E 00 00 A3 90 89 40 00 E8 4D 0C 00 00 E8 8F 0B 00 00 E8 22 FE FF FF 89 75 D0 8D 45 A4 50 FF 15 0C 61 40 00 E8 20 0B 00 00 89 45 9C F6 45 D0 01 74 06 0F B7 45 D4 EB 03 6A 0A 58 50 FF 75 9C 56 56 FF 15 08 61 40 00 50 E8 5A E9 FF FF 89 45 A0 50 E8 10 FE FF FF 8B 45 }

condition:
    	$a0 or $a1
}

    
rule Dev_C___4_9_9_2____Bloodshed_Software
{
meta:
    description = "Dev-C++ 4.9.9.2 -> Bloodshed Software"
strings:
    	$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D }

condition:
    	$a0 at manape.ep
}

  
rule Patch_Creation_Wizard_v1_2_Memory_Patch
{
meta:
    description = "Patch Creation Wizard v1.2 Memory Patch"
strings:
    	$a0 = { 6A 00 E8 9B 02 00 00 A3 7A 33 40 00 6A 00 68 8E 10 40 00 6A 00 6A 01 50 E8 B5 02 00 00 68 5A 31 40 00 68 12 31 40 00 6A 00 6A 00 6A 04 6A 01 6A 00 6A 00 68 A2 30 40 00 6A 00 E8 51 02 00 00 85 C0 74 31 FF 35 62 31 40 00 6A 00 6A 30 E8 62 02 00 00 E8 0B 01 00 00 FF 35 5A 31 40 00 E8 22 02 00 00 FF 35 5E 31 40 00 E8 53 02 00 00 6A 00 E8 22 02 00 00 6A 10 68 F7 30 40 00 68 FE 30 40 00 6A 00 E8 63 02 00 00 6A 00 E8 08 02 00 00 55 8B EC 56 51 57 8B 45 0C 98 3D 10 01 00 00 75 6B 6A 01 FF 35 7A 33 40 00 E8 38 02 00 00 50 6A 01 68 80 00 00 00 FF 75 08 E8 34 02 00 00 68 00 30 40 00 6A 65 FF 75 08 E8 2B 02 00 00 68 51 30 40 00 6A 67 FF 75 08 E8 1C 02 00 00 68 A2 30 40 00 6A 66 FF 75 08 E8 0D 02 00 00 8B 45 08 A3 7E 33 40 00 68 3B 11 40 00 68 E8 03 00 00 68 9A 02 00 }

condition:
    	$a0
}

    
rule Microsoft_Visual_C___7_0_Custom
{
meta:
    description = "Microsoft Visual C++ 7.0 Custom"
strings:
    	$a0 = { 60 BE 00 B0 44 00 8D BE 00 60 FB FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_Studio__NET
{
meta:
    description = "Microsoft Visual Studio .NET"
strings:
    	$a0 = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
    	$a0 at manape.ep
}

    
rule LCC_Win32
{
meta:
    description = "LCC-Win32"
strings:
    	$a0 = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 10 30 40 00 68 9A 10 40 }

condition:
    	$a0 at manape.ep
}

    
rule Inno_Setup_Module
{
meta:
    description = "Inno Setup Module"
strings:
    	$a0 = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43 }
	$a1 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF }

condition:
    	$a0 at manape.ep or $a1
}

    
rule Borland_Pascal_v7_0_Protected_Mode
{
meta:
    description = "Borland Pascal v7.0 Protected Mode"
strings:
    	$a0 = { B8 ?? ?? BB ?? ?? 8E D0 8B E3 8C D8 8E C0 0E 1F A1 ?? ?? 25 ?? ?? A3 ?? ?? E8 ?? ?? 83 3E ?? ?? ?? 75 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C_2_0
{
meta:
    description = "Microsoft Visual C 2.0"
strings:
    	$a0 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 }

condition:
    	$a0 at manape.ep
}

    
rule MS_Run_Time_Library_1992__13_
{
meta:
    description = "MS Run-Time Library 1992 (13)"
strings:
    	$a0 = { BF ?? ?? 8E DF FA 8E D7 81 C4 ?? ?? FB 33 DB B8 ?? ?? CD 21 }

condition:
    	$a0 at manape.ep
}

    
rule Borland_C___1992__1994
{
meta:
    description = "Borland C++ 1992, 1994"
strings:
    	$a0 = { 8C C8 8E D8 8C 1E ?? ?? 8C 06 ?? ?? 8C 06 ?? ?? 8C 06 }

condition:
    	$a0 at manape.ep
}

    
rule Turbo_C___3_0_1990
{
meta:
    description = "Turbo C++ 3.0 1990"
strings:
    	$a0 = { 8C CA 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B ?? ?? ?? 8E DA A3 ?? ?? 8C 06 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C___6_0_SFX_Custom
{
meta:
    description = "Microsoft Visual C++ 6.0 SFX Custom"
strings:
    	$a0 = { E8 21 48 00 00 E9 16 FE FF FF 51 C7 01 08 B4 00 30 E8 A4 48 00 00 59 C3 56 8B F1 E8 EA FF FF FF F6 ?? ?? ?? ?? 74 07 56 E8 F6 04 00 00 59 8B C6 5E C2 04 00 8B 44 24 04 83 C1 09 51 83 C0 09 50 }

condition:
    	$a0 at manape.ep
}

    
rule Nullsoft_Install_System_2_0
{
meta:
    description = "Nullsoft Install System 2.0"
strings:
    	$a0 = { 83 EC 0C 53 55 56 57 C7 44 24 10 ?? ?? ?? ?? 33 DB C6 44 24 14 20 FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? BE ?? ?? ?? ?? BF ?? ?? ?? ?? 56 57 A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? E8 8D FF FF FF 8B 2D ?? ?? ?? ?? 85 C0 }
	$a1 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }

condition:
    	$a0 at manape.ep or $a1
}

    
rule Microsoft_Visual_C___v6_0_SPx
{
meta:
    description = "Microsoft Visual C++ v6.0 SPx"
strings:
    	$a0 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 8B F0 8A ?? 3C 22 }
	$a1 = { 55 8B EC 83 EC 44 56 FF 15 ?? ?? ?? ?? 6A 01 8B F0 FF 15 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule FreeBASIC_v0_11
{
meta:
    description = "FreeBASIC v0.11"
strings:
    	$a0 = { E8 ?? ?? 00 00 E8 01 00 00 00 C3 55 89 E5 }

condition:
    	$a0 at manape.ep
}

    
rule CA_Visual_Objects_2_0___2_5
{
meta:
    description = "CA Visual Objects 2.0 - 2.5"
strings:
    	$a0 = { 89 25 ?? ?? ?? ?? 33 ED 55 8B EC E8 ?? ?? ?? ?? 8B D0 81 E2 FF 00 00 00 89 15 ?? ?? ?? ?? 8B D0 C1 EA 08 81 E2 FF 00 00 00 A3 ?? ?? ?? ?? D1 E0 0F 93 C3 33 C0 8A C3 A3 ?? ?? ?? ?? 68 FF 00 00 00 E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? BB }
	$a1 = { 89 25 ?? ?? ?? ?? 33 ED 55 8B EC E8 ?? ?? ?? ?? 8B D0 81 E2 FF 00 00 00 89 15 ?? ?? ?? ?? 8B D0 C1 EA 08 81 E2 FF 00 00 00 A3 ?? ?? ?? ?? D1 E0 0F 93 C3 33 C0 8A C3 A3 ?? ?? ?? ?? 68 FF 00 00 00 E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? BB ?? ?? ?? ?? C7 03 44 00 00 00 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule MS_Run_Time_Library_1990__07_
{
meta:
    description = "MS Run-Time Library 1990 (07)"
strings:
    	$a0 = { 2E 8C 1E ?? ?? BB ?? ?? 8E DB 1E E8 ?? ?? 1F 8B 1E ?? ?? 0B DB 74 ?? 8C D1 8B D4 FA 8E D3 BC ?? ?? FB }

condition:
    	$a0 at manape.ep
}

    
rule MS_Run_Time_Library_1990__1992__09_
{
meta:
    description = "MS Run-Time Library 1990, 1992 (09)"
strings:
    	$a0 = { B4 30 CD 21 3C 02 73 ?? C3 8C DF 8B 36 ?? ?? 2E }

condition:
    	$a0 at manape.ep
}

    
rule MetaWare_High_C_Run_Time_Library___Phar_Lap_DOS_Extender_1983_89
{
meta:
    description = "MetaWare High C Run-Time Library + Phar Lap DOS Extender 1983-89"
strings:
    	$a0 = { B8 ?? ?? 50 B8 ?? ?? 50 CB }

condition:
    	$a0 at manape.ep
}

    
rule Borland_C___for_Win16_1991
{
meta:
    description = "Borland C++ for Win16 1991"
strings:
    	$a0 = { 9A FF FF 00 00 0B C0 75 ?? E9 ?? ?? 8C ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? 89 ?? ?? ?? B8 FF FF 50 9A FF FF 00 00 }

condition:
    	$a0 at manape.ep
}

    
rule Borland_C___DLL
{
meta:
    description = "Borland C++ DLL"
strings:
    	$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3 8B }
	$a1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 ?? ?? ?? ?? A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 8B }
	$a2 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep or $a2
}

    
rule Microsoft_Visual_C___vx_x
{
meta:
    description = "Microsoft Visual C++ vx.x"
strings:
    	$a0 = { 53 55 56 8B ?? ?? ?? 85 F6 57 B8 ?? ?? ?? ?? 75 ?? 8B ?? ?? ?? ?? ?? 85 C9 75 ?? 33 C0 5F 5E 5D 5B C2 }
	$a1 = { 55 8B EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 04 }
	$a2 = { 55 8B EC 56 57 BF ?? ?? ?? ?? 8B ?? ?? 3B F7 0F }

condition:
    	$a0 at manape.ep or $a1 at manape.ep or $a2 at manape.ep
}

    
rule Borland_Delphi_3____Portions_Copyright__c__1983_97_Borland__h_
{
meta:
    description = "Borland Delphi 3 -> Portions Copyright (c) 1983,97 Borland (h)"
strings:
    	$a0 = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 37 20 42 6F 72 6C 61 6E 64 00 }

condition:
    	$a0
}

    
rule Microsoft_Visual_C___6_0_DLL__Debug_
{
meta:
    description = "Microsoft Visual C++ 6.0 DLL (Debug)"
strings:
    	$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 ?? ?? 83 }

condition:
    	$a0
}

    
rule CC_v2_61_Beta
{
meta:
    description = "CC v2.61 Beta"
strings:
    	$a0 = { BA ?? ?? B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB }

condition:
    	$a0 at manape.ep
}

    
rule PowerBASIC_CC_3_0x
{
meta:
    description = "PowerBASIC/CC 3.0x"
strings:
    	$a0 = { 55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? ?? 00 04 00 0F 85 }

condition:
    	$a0 at manape.ep
}

    
rule Installer_VISE_Custom
{
meta:
    description = "Installer VISE Custom"
strings:
    	$a0 = { 55 8B EC 6A FF 68 ?? ?? 40 00 68 ?? ?? 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 ?? ?? 40 00 33 D2 8A D4 89 15 ?? ?? 40 00 8B C8 81 E1 FF 00 00 00 89 0D }

condition:
    	$a0 at manape.ep
}

    
rule Turbo_or_Borland_Pascal_v7_0
{
meta:
    description = "Turbo or Borland Pascal v7.0"
strings:
    	$a0 = { 9A ?? ?? ?? ?? C8 ?? ?? ?? 9A ?? ?? ?? ?? 09 C0 75 ?? EB ?? 8D ?? ?? ?? 16 57 6A ?? 9A ?? ?? ?? ?? BF ?? ?? 1E 57 68 }

condition:
    	$a0 at manape.ep
}

    
rule MASM32
{
meta:
    description = "MASM32"
strings:
    	$a0 = { 6A ?? 68 00 30 40 00 68 ?? 30 40 00 6A 00 E8 07 00 00 00 6A 00 E8 06 00 00 00 FF 25 08 20 }

condition:
    	$a0 at manape.ep
}

    
rule Nullsoft_PIMP_Install_System_v1_x
{
meta:
    description = "Nullsoft PIMP Install System v1.x"
strings:
    	$a0 = { 83 EC 5C 53 55 56 57 FF 15 ?? ?? ?? 00 }

condition:
    	$a0 at manape.ep
}

    
rule MS_Run_Time_Library__OS_2____FORTRAN_Compiler_1989
{
meta:
    description = "MS Run-Time Library (OS/2) & FORTRAN Compiler 1989"
strings:
    	$a0 = { B4 30 CD 21 86 E0 2E A3 ?? ?? 3D ?? ?? 73 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C___v7_0__64_Bit_
{
meta:
    description = "Microsoft Visual C++ v7.0 (64 Bit)"
strings:
    	$a0 = { 41 00 00 00 00 00 00 00 63 00 00 00 00 00 ?? 00 ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 20 ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? ?? ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 }
	$a1 = { 41 00 00 00 00 00 00 00 63 00 00 00 00 00 ?? 00 ?? ?? ?? ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 20 ?? ?? 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 }

condition:
    	$a0 at manape.ep or $a1
}

    
rule Borland_Delphi_v5_0_KOL
{
meta:
    description = "Borland Delphi v5.0 KOL"
strings:
    	$a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF 8B C0 00 00 00 00 00 00 00 00 00 00 00 }

condition:
    	$a0 at manape.ep
}

    
rule FreePascal_1_0_4_Win32_____Berczi_Gabor__Pierre_Muller___Peter_Vreman_
{
meta:
    description = "FreePascal 1.0.4 Win32 -> (Berczi Gabor, Pierre Muller & Peter Vreman)"
strings:
    	$a0 = { 55 89 E5 C6 05 ?? ?? ?? ?? 00 E8 ?? ?? ?? ?? 55 31 ED 89 E0 A3 ?? ?? ?? ?? 66 8C D5 89 2D ?? ?? ?? ?? DB E3 D9 2D ?? ?? ?? ?? 31 ED E8 ?? ?? ?? ?? 5D E8 ?? ?? ?? ?? C9 C3 }

condition:
    	$a0
}

    
rule Microsoft_C_for_Windows__1_
{
meta:
    description = "Microsoft C for Windows (1)"
strings:
    	$a0 = { 33 ED 55 9A ?? ?? ?? ?? 0B C0 74 }

condition:
    	$a0 at manape.ep
}

    
rule Borland_C__
{
meta:
    description = "Borland C++"
strings:
    	$a0 = { A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 57 51 33 C0 BF ?? ?? ?? ?? B9 ?? ?? ?? ?? 3B CF 76 05 2B CF FC F3 AA 59 5F }

condition:
    	$a0 at manape.ep
}

    
rule Dev_C___v5
{
meta:
    description = "Dev-C++ v5"
strings:
    	$a0 = { 55 89 E5 83 EC 14 6A ?? FF 15 ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 }

condition:
    	$a0
}

    
rule CreateInstall_v2003_3_5
{
meta:
    description = "CreateInstall v2003.3.5"
strings:
    	$a0 = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 FF 15 E4 80 40 00 50 FF 15 E0 80 40 00 8B 0D 00 50 40 00 E8 68 FF FF FF B9 40 0D 03 00 89 44 24 14 E8 5A FF FF FF 68 00 02 00 00 8B 2D D0 80 40 00 89 44 24 1C 8D 44 24 20 50 53 FF D5 8D 4C 24 1C 53 68 00 00 00 80 8B 3D CC 80 40 00 6A 03 53 6A 03 68 00 00 00 80 51 FF D7 8B F0 53 8D 44 24 14 8B 0D 00 50 40 00 8B 54 24 18 50 51 52 56 FF 15 C8 80 40 00 85 C0 0F 84 40 02 00 00 8B 15 00 50 40 00 3B 54 24 10 0F 85 30 02 00 00 6A FF A1 04 50 40 00 2B D0 8B 4C 24 18 03 C8 E8 9F FE FF FF 3B 05 10 50 40 00 0F 85 10 02 00 00 56 FF }
	$a1 = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 FF 15 E4 80 40 }

condition:
    	$a0 or $a1
}

    
rule Microsoft_Visual_C___6_0___8_0
{
meta:
    description = "Microsoft Visual C++ 6.0 - 8.0"
strings:
    	$a0 = { 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 8B 44 24 10 89 6C 24 10 8D 6C 24 10 2B E0 53 56 57 8B 45 F8 89 65 E8 50 8B 45 FC C7 45 FC FF FF FF FF 89 45 F8 C3 8B 4D F0 64 89 0D 00 00 00 00 59 5F 5E 5B C9 51 C3 }
	$a1 = { 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 8B 44 24 10 89 6C 24 10 8D 6C 24 10 2B E0 53 56 57 8B 45 F8 89 65 E8 50 8B 45 FC C7 45 FC FF FF FF FF 89 45 F8 8D 45 F0 64 A3 00 00 00 00 C3 8B 4D F0 64 89 0D 00 00 00 00 59 5F 5E 5B C9 51 }
	$a2 = { 3D 00 10 00 00 73 0E F7 D8 03 C4 83 C0 04 85 00 94 8B 00 50 C3 51 8D 4C 24 08 81 E9 00 10 00 00 2D 00 10 00 00 85 01 3D 00 10 00 00 73 EC 2B C8 8B C4 85 01 8B E1 8B 08 8B 40 04 50 C3 }
	$a3 = { 8B 44 24 08 85 C0 0F 84 ?? ?? ?? ?? 83 F8 01 8B 0D ?? ?? ?? ?? 8B 09 89 0D ?? ?? ?? ?? 0F 85 ?? ?? ?? ?? 68 80 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 59 A3 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 83 20 00 A1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? A3 ?? ?? ?? ?? E8 }
	$a4 = { 8B 44 24 08 8B 4C 24 10 0B C8 8B 4C 24 0C 75 09 8B 44 24 04 F7 E1 C2 10 00 53 F7 E1 8B D8 8B 44 24 08 F7 64 24 14 03 D8 8B 44 24 08 F7 E1 03 D3 5B C2 10 00 }
	$a5 = { 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 8B 44 24 10 89 6C 24 10 8D 6C 24 10 2B E0 53 56 57 8B 45 F8 89 65 E8 50 8B 45 FC C7 45 FC FF FF FF FF 89 45 F8 8D 45 F0 64 A3 00 00 00 00 C3 8B 4D F0 64 89 0D 00 00 00 00 59 5F 5E 5B C9 51 C3 }

condition:
    	$a0 or $a1 at manape.ep or $a2 or $a3 or $a4 or $a5
}

    
rule Microsoft_Visual_C___v7_0
{
meta:
    description = "Microsoft Visual C++ v7.0"
strings:
    	$a0 = { 6A 0C 68 88 BF 01 10 E8 B8 1C 00 00 33 C0 40 89 45 E4 8B 75 0C 33 FF 3B F7 75 0C 39 3D 6C 1E 12 10 0F 84 B3 00 00 00 89 7D FC 3B F0 74 05 83 FE 02 75 31 A1 98 36 12 10 3B C7 74 0C FF 75 10 56 }
	$a1 = { 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF ?? ?? ?? ?? 8B C7 E8 ?? ?? ?? ?? 89 65 ?? 8B F4 89 3E 56 FF 15 ?? ?? ?? ?? 8B 4E ?? 89 0D ?? ?? ?? ?? 8B 46 ?? A3 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Microsoft_Visual_C___v5_0
{
meta:
    description = "Microsoft Visual C++ v5.0"
strings:
    	$a0 = { 55 8B EC 6A FF 68 68 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 53 56 57 }

condition:
    	$a0 at manape.ep
}

    
rule MinGW_v3_2_x__main_
{
meta:
    description = "MinGW v3.2.x (main)"
strings:
    	$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 E4 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 E4 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 00 41 40 00 89 EC 5D }
	$a1 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 E4 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 E4 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 00 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 F4 40 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 53 83 EC 24 C7 04 24 A0 11 40 00 E8 8D 07 00 00 83 EC 04 E8 85 02 00 00 C7 04 24 00 20 40 00 8B 15 10 20 40 00 8D 4D F8 C7 45 F8 00 00 00 00 89 4C 24 10 89 54 24 0C 8D 55 F4 89 54 24 08 C7 44 24 04 04 20 40 00 E8 02 07 00 00 A1 20 20 40 00 85 C0 74 76 A3 30 20 40 00 A1 F0 40 40 00 85 C0 74 1F 89 04 24 E8 C3 06 00 00 8B 1D 20 20 40 00 89 04 24 89 5C 24 04 E8 C1 06 00 00 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Dev_C___v4
{
meta:
    description = "Dev-C++ v4"
strings:
    	$a0 = { 55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 ?? ?? ?? 00 FF D0 E8 ?? FF FF FF }

condition:
    	$a0
}

    
rule MS_Visual_C___v_8__h_good_sig__but_is_it_MSVC__
{
meta:
    description = "MS Visual C++ v.8 (h-good sig, but is it MSVC?)"
strings:
    	$a0 = { E8 ?? ?? ?? ?? E9 8D FE FF FF CC CC CC CC CC 66 81 3D 00 00 00 01 4D 5A 74 04 33 C0 EB 51 A1 3C 00 00 01 81 B8 00 00 00 01 50 45 00 00 75 EB 0F B7 88 18 00 00 01 81 F9 0B 01 00 00 74 1B 81 F9 0B 02 00 00 75 D4 83 B8 84 00 00 01 0E 76 CB 33 C9 39 88 F8 00 }
	$a1 = { E8 ?? ?? ?? ?? E9 8D FE FF FF CC CC CC CC CC 66 81 3D 00 00 00 01 4D 5A 74 04 33 C0 EB 51 A1 3C 00 00 01 81 B8 00 00 00 01 50 45 00 00 75 EB 0F B7 88 18 00 00 01 81 F9 0B 01 00 00 74 1B 81 F9 0B 02 00 00 75 D4 83 B8 84 00 00 01 0E 76 CB 33 C9 39 88 F8 00 00 01 EB 11 83 B8 74 00 00 01 0E 76 B8 33 C9 39 88 E8 00 00 01 0F 95 C1 8B C1 6A 01 A3 ?? ?? ?? 01 E8 ?? ?? 00 00 50 FF ?? ?? ?? 00 01 83 0D ?? ?? ?? 01 FF 83 0D ?? ?? ?? 01 FF 59 59 FF 15 ?? ?? 00 01 8B 0D ?? ?? ?? 01 89 08 FF 15 ?? ?? 00 01 8B 0D ?? ?? ?? 01 89 08 A1 ?? ?? 00 01 8B 00 A3 ?? ?? ?? 01 E8 ?? ?? 00 00 83 3D ?? ?? ?? 01 00 75 0C 68 ?? ?? ?? 01 FF 15 ?? ?? 00 01 59 E8 ?? ?? 00 00 33 C0 C3 CC CC CC CC CC }

condition:
    	$a0 or $a1 at manape.ep
}

    
rule WATCOM_C_C___32_Run_Time_System_1988_1995
{
meta:
    description = "WATCOM C/C++ 32 Run-Time System 1988-1995"
strings:
    	$a0 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D 54 }
	$a1 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 54 43 4F 4D ?? 43 2F 43 2B 2B 33 32 ?? 52 75 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule WATCOM_C_C___32_Run_Time_System_1988_1994
{
meta:
    description = "WATCOM C/C++ 32 Run-Time System 1988-1994"
strings:
    	$a0 = { FB 83 ?? ?? 89 E3 89 ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 66 ?? ?? ?? 66 ?? ?? ?? ?? ?? BB ?? ?? ?? ?? 29 C0 B4 30 CD 21 }

condition:
    	$a0 at manape.ep
}

    
rule MinGW_GCC_v2_x
{
meta:
    description = "MinGW GCC v2.x"
strings:
    	$a0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 00 }
	$a1 = { 55 89 E5 E8 ?? ?? ?? ?? C9 C3 ?? ?? 45 58 45 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule MS_Run_Time_Library_1992__11_
{
meta:
    description = "MS Run-Time Library 1992 (11)"
strings:
    	$a0 = { B4 51 CD 21 8E DB B8 ?? ?? 83 E8 ?? 8E C0 33 F6 33 FF B9 ?? ?? FC F3 A5 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Basic_Compiler_v5_60_1982_97
{
meta:
    description = "Microsoft Basic Compiler v5.60 1982-97"
strings:
    	$a0 = { 9A ?? ?? ?? ?? 9A ?? ?? ?? ?? 9A ?? ?? ?? ?? 33 DB BA ?? ?? 9A ?? ?? ?? ?? C7 06 ?? ?? ?? ?? 33 DB }

condition:
    	$a0 at manape.ep
}

    
rule Turbo_Pascal_v2_0_1984
{
meta:
    description = "Turbo Pascal v2.0 1984"
strings:
    	$a0 = { 90 90 CD AB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 34 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_Basic_v5_0_v6_0
{
meta:
    description = "Microsoft Visual Basic v5.0/v6.0"
strings:
    	$a0 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 00 00 00 00 30 00 00 00 }

condition:
    	$a0 at manape.ep
}

    
rule Turbo_C_1990_or_Turbo_C_1988
{
meta:
    description = "Turbo C 1990 or Turbo C 1988"
strings:
    	$a0 = { BA ?? ?? 2E 89 ?? ?? ?? B4 30 CD 21 8B ?? ?? ?? 8B ?? ?? ?? 8E DA }

condition:
    	$a0 at manape.ep
}

    
rule MinGW_GCC_DLL_v2xx
{
meta:
    description = "MinGW GCC DLL v2xx"
strings:
    	$a0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

condition:
    	$a0 at manape.ep
}

    
rule MSVC___DLL_v_8__typical_OEP_recognized___h_
{
meta:
    description = "MSVC++ DLL v.8 (typical OEP recognized - h)"
strings:
    	$a0 = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D ?? ?? ?? ?? 00 EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 ?? ?? ?? ?? 85 C0 74 09 57 56 53 FF D0 85 C0 74 0C 57 56 53 E8 ?? ?? ?? FF 85 C0 75 04 33 C0 EB 4E 57 56 53 E8 ?? ?? ?? FF 83 FE 01 89 45 0C 75 0C 85 C0 75 37 57 50 53 E8 ?? ?? ?? FF 85 F6 74 05 83 FE 03 75 26 57 56 53 E8 ?? ?? ?? FF 85 C0 75 03 21 45 0C 83 7D 0C 00 74 11 A1 ?? ?? ?? ?? 85 C0 74 08 57 56 53 FF D0 89 45 0C 8B 45 0C 5F 5E 5B 5D C2 0C 00 }

condition:
    	$a0 at manape.ep
}

    
rule PowerBASIC_Win_7_0x
{
meta:
    description = "PowerBASIC/Win 7.0x"
strings:
    	$a0 = { 55 8B EC 53 56 57 BB 00 ?? 40 00 66 2E F7 05 ?? ?? 40 00 04 00 0F 85 DB 00 00 00 }

condition:
    	$a0 at manape.ep
}

    
rule Lattice_C_v3_0
{
meta:
    description = "Lattice C v3.0"
strings:
    	$a0 = { FA B8 ?? ?? 8E D8 B8 ?? ?? 8E }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C___v7_1_EXE
{
meta:
    description = "Microsoft Visual C++ v7.1 EXE"
strings:
    	$a0 = { 6A ?? 68 ?? ?? ?? 01 E8 ?? ?? 00 00 66 81 3D 00 00 00 01 4D 5A 75 ?? A1 3C 00 00 01 ?? ?? 00 00 00 01 }
	$a1 = { 6A ?? 68 ?? ?? ?? ?? E8 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Microsoft_Windows_Update_CAB_SFX_module
{
meta:
    description = "Microsoft Windows Update CAB SFX module"
strings:
    	$a0 = { E9 C5 FA FF FF 55 8B EC 56 8B 75 08 68 04 08 00 00 FF D6 59 33 C9 3B C1 75 0F 51 6A 05 FF 75 28 E8 2E 11 00 00 33 C0 EB 69 8B 55 0C 83 88 88 00 00 00 FF 83 88 84 00 00 00 FF 89 50 04 8B 55 10 89 50 0C 8B 55 14 89 50 10 8B 55 18 89 50 14 8B 55 1C 89 50 18 8B 55 20 89 50 1C 8B 55 24 89 50 20 8B 55 28 89 48 48 89 48 44 89 48 4C B9 FF FF 00 00 89 70 08 89 10 66 C7 80 B2 00 00 00 0F 00 89 88 A0 00 00 00 89 88 A8 00 00 00 89 88 A4 00 00 }
	$a1 = { E9 C5 FA FF FF 55 8B EC 56 8B 75 08 68 04 08 00 00 FF D6 59 33 C9 3B C1 75 0F 51 6A 05 FF 75 28 E8 2E 11 00 00 33 C0 EB 69 8B 55 0C 83 88 88 00 00 00 FF 83 88 84 00 00 00 FF 89 50 04 8B 55 10 89 50 0C 8B 55 14 89 50 10 8B 55 18 89 50 14 8B 55 1C 89 50 18 }

condition:
    	$a0 or $a1
}

    
rule MS_Run_Time_Library_1987
{
meta:
    description = "MS Run-Time Library 1987"
strings:
    	$a0 = { B4 30 CD 21 3C 02 73 ?? 9A ?? ?? ?? ?? B8 ?? ?? 50 9A ?? ?? ?? ?? 92 }

condition:
    	$a0 at manape.ep
}

    
rule TASM___MASM
{
meta:
    description = "TASM / MASM"
strings:
    	$a0 = { 6A 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 }

condition:
    	$a0 at manape.ep
}

    
rule Borland_Delphi_v3_0
{
meta:
    description = "Borland Delphi v3.0"
strings:
    	$a0 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 55 8B EC 33 C0 }

condition:
    	$a0 at manape.ep
}

    
rule Reg2Exe_2_22_2_23___by_Jan_Vorel
{
meta:
    description = "Reg2Exe 2.22/2.23 - by Jan Vorel"
strings:
    	$a0 = { 6A 00 E8 2F 1E 00 00 A3 C4 35 40 00 E8 2B 1E 00 00 6A 0A 50 6A 00 FF 35 C4 35 40 00 E8 07 00 00 00 50 E8 1B 1E 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 C8 35 40 00 E8 76 16 00 00 83 C4 0C 8B 44 24 04 A3 CC 35 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 EC 1D 00 00 A3 C8 35 40 00 E8 62 1D 00 00 E8 92 1A 00 00 E8 80 16 00 00 E8 13 14 00 00 68 01 00 00 00 68 08 36 40 00 68 00 00 00 00 8B 15 08 36 40 00 E8 71 3F 00 00 B8 00 00 10 00 BB 01 00 00 00 E8 82 3F 00 00 FF 35 48 31 40 00 B8 00 01 00 00 E8 0D 13 00 00 8D 0D EC 35 40 00 5A E8 F2 13 00 00 68 00 01 00 00 FF 35 EC 35 40 00 E8 84 1D 00 00 A3 F4 35 40 00 FF 35 48 31 40 00 FF 35 F4 35 40 00 FF 35 EC 35 40 00 E8 }
	$a1 = { 6A 00 E8 2F 1E 00 00 A3 C4 35 40 00 E8 2B 1E 00 00 6A 0A 50 6A 00 FF 35 C4 35 40 00 E8 07 00 00 00 50 E8 1B 1E 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 C8 35 40 00 E8 76 16 00 00 83 C4 0C 8B 44 24 04 A3 CC 35 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule MinGW_3_2_x__Dll_main_
{
meta:
    description = "MinGW 3.2.x (Dll_main)"
strings:
    	$a0 = { 55 89 E5 83 EC 18 89 75 FC 8B 75 0C 89 5D F8 83 FE 01 74 5C 89 74 24 04 8B 55 10 89 54 24 08 8B 55 08 89 14 24 E8 96 01 00 00 83 EC 0C 83 FE 01 89 C3 74 2C 85 F6 75 0C 8B 0D 00 30 00 10 85 C9 75 10 31 DB 89 D8 8B 5D F8 8B 75 FC 89 EC 5D C2 0C 00 E8 59 00 }

condition:
    	$a0
}

    
rule Turbo_C_or_Borland_C__
{
meta:
    description = "Turbo C or Borland C++"
strings:
    	$a0 = { BA ?? ?? 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA }

condition:
    	$a0 at manape.ep
}

    
rule MinGW_v3_2_x__WinMain_
{
meta:
    description = "MinGW v3.2.x (WinMain)"
strings:
    	$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 FC 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 FC 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 18 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 0C 41 40 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 53 83 EC 24 C7 04 24 A0 11 40 00 E8 5D 08 00 00 83 EC 04 E8 55 03 00 00 C7 04 24 00 20 40 00 8B 15 10 20 40 00 8D 4D F8 C7 45 F8 00 00 00 00 89 4C 24 10 89 54 24 0C 8D 55 F4 89 54 24 08 C7 44 24 04 04 20 40 00 E8 D2 07 00 00 A1 20 20 40 00 85 C0 74 76 A3 30 20 40 00 A1 08 41 40 00 85 C0 74 1F 89 04 24 E8 93 07 00 00 8B 1D 20 20 40 00 89 04 24 89 5C 24 04 E8 91 07 00 00 }
	$a1 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 FC 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 FC 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 18 41 40 00 89 EC 5D }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Microsoft_Visual_C____Basic__NET
{
meta:
    description = "Microsoft Visual C# / Basic .NET"
strings:
    	$a0 = { FF 25 00 20 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C___7_0_MFC
{
meta:
    description = "Microsoft Visual C++ 7.0 MFC"
strings:
    	$a0 = { 6A 60 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BF 94 00 00 00 8B C7 E8 ?? ?? ?? ?? 89 }

condition:
    	$a0 at manape.ep
}

    
rule Obsidium_1_3_0_37____Obsidium_Software
{
meta:
    description = "Obsidium 1.3.0.37 -> Obsidium Software"
strings:
    	$a0 = { EB 02 ?? ?? E8 26 00 00 00 EB 03 ?? ?? ?? EB 01 ?? 8B 54 24 0C EB 04 ?? ?? ?? ?? 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 ?? ?? C3 EB 01 ?? EB 04 ?? ?? ?? ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 ?? ?? ?? 50 EB 03 ?? ?? ?? 33 C0 EB 03 ?? ?? ?? 8B 00 EB 04 ?? ?? ?? ?? C3 EB 03 ?? ?? ?? E9 FA 00 00 00 EB 03 ?? ?? ?? E8 D5 FF FF FF EB 04 ?? ?? ?? ?? EB 01 ?? 58 EB 02 ?? ?? EB 03 ?? ?? ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 ?? ?? ?? E8 23 27 00 00 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_C_v1_04
{
meta:
    description = "Microsoft C v1.04"
strings:
    	$a0 = { FA B8 ?? ?? 8E D8 8E D0 26 8B ?? ?? ?? 2B D8 F7 ?? ?? ?? 75 ?? B1 04 D3 E3 EB }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C___8
{
meta:
    description = "Microsoft Visual C++ 8"
strings:
    	$a0 = { E8 ?? ?? 00 00 E9 ?? ?? FF FF }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C__v7_0___Basic__NET
{
meta:
    description = "Microsoft Visual C# v7.0 / Basic .NET"
strings:
    	$a0 = { FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

condition:
    	$a0
}

    
rule Lattice_C_v1_01
{
meta:
    description = "Lattice C v1.01"
strings:
    	$a0 = { FA B8 ?? ?? 05 ?? ?? B1 ?? D3 E8 8C CB 03 C3 8E D8 8E D0 26 ?? ?? ?? ?? 2B D8 F7 ?? ?? ?? 75 ?? B1 ?? D3 E3 EB }

condition:
    	$a0 at manape.ep
}

    
rule MingWin32_GCC_3_x
{
meta:
    description = "MingWin32 GCC 3.x"
strings:
    	$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 ?? ?? 40 00 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C___6_0_DLL
{
meta:
    description = "Microsoft Visual C++ 6.0 DLL"
strings:
    	$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 75 09 83 3D ?? ?? ?? ?? ?? EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 ?? ?? ?? ?? 85 C0 74 09 57 56 53 FF D0 85 C0 74 0C 57 56 53 E8 15 FF FF FF 85 C0 75 04 33 C0 EB 4E }

condition:
    	$a0
}

    
rule Microsoft_Visual_C___7_0_DLL
{
meta:
    description = "Microsoft Visual C++ 7.0 DLL"
strings:
    	$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 }

condition:
    	$a0
}

    
rule Microsoft_Visual_C___8_0
{
meta:
    description = "Microsoft Visual C++ 8.0"
strings:
    	$a0 = { 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 ?? ?? ?? ?? ?? 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 00 ?? ?? 00 00 00 00 00 ?? ?? ?? 00 00 }
	$a1 = { 83 3D ?? ?? ?? ?? 00 74 1A 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 59 74 0B FF 74 24 04 FF 15 ?? ?? ?? ?? 59 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 59 59 75 54 56 57 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BE ?? ?? ?? ?? 8B C6 BF }
	$a2 = { 6A 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 94 00 00 00 53 6A 00 8B ?? ?? ?? ?? ?? FF D7 50 FF ?? ?? ?? ?? ?? 8B F0 85 F6 75 0A 6A 12 E8 ?? ?? ?? ?? 59 EB 18 89 1E 56 FF ?? ?? ?? ?? ?? 56 85 C0 75 14 50 FF D7 50 FF ?? ?? ?? ?? ?? B8 }
	$a3 = { 48 83 EC 28 E8 ?? ?? 00 00 48 83 C4 28 E9 ?? ?? FF FF CC CC CC CC CC CC CC CC CC CC CC CC CC CC }

condition:
    	$a0 at manape.ep or $a1 or $a2 at manape.ep or $a3 at manape.ep
}

    
rule Nullsoft_Install_System_v2_0b4
{
meta:
    description = "Nullsoft Install System v2.0b4"
strings:
    	$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 68 E4 91 40 00 56 FF D3 E8 7C FF FF FF 85 C0 0F 84 59 01 00 00 BE E0 66 42 00 56 FF 15 68 70 40 00 68 D8 91 40 00 56 E8 FE 27 00 00 57 FF 15 BC 70 40 00 BE 00 C0 42 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 C0 42 00 22 A3 E0 6E 42 00 8B C6 75 0A C6 44 24 13 22 B8 01 C0 42 00 8B 3D 10 72 40 00 EB 09 3A 4C 24 13 74 09 50 FF D7 8A 08 84 C9 75 F1 50 FF D7 8B F0 89 74 24 1C EB 05 56 FF D7 8B F0 80 3E 20 74 F6 80 3E 2F 75 44 46 80 3E 53 75 0C 8A 46 01 0C 20 3C 20 75 03 83 CD 02 81 3E 4E 43 52 }
	$a1 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 }
	$a2 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 }
	$a3 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 40 00 03 C6 50 E8 78 29 00 00 56 E8 47 2B 00 00 6A 00 56 FF D3 56 57 E8 EA 25 00 00 85 C0 75 0D C7 44 24 14 58 91 40 00 E9 72 02 00 00 57 FF 15 24 71 40 00 68 EC 91 40 00 57 E8 43 }

condition:
    	$a0 or $a1 or $a2 or $a3
}

    
rule InstallShield_2000
{
meta:
    description = "InstallShield 2000"
strings:
    	$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 C4 ?? 53 56 57 }

condition:
    	$a0 at manape.ep
}

    
rule InstallShield_3_x_Custom
{
meta:
    description = "InstallShield 3.x Custom"
strings:
    	$a0 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 00 A0 40 00 68 34 76 40 00 50 64 89 25 00 00 00 00 83 EC 60 53 56 57 89 65 E8 FF 15 8C E3 40 00 A3 70 B1 40 00 33 C0 A0 71 B1 40 00 A3 7C B1 40 00 A1 70 B1 }

condition:
    	$a0 at manape.ep
}

    
rule MingWin32___Dev_C___v4_9_9_1__h_
{
meta:
    description = "MingWin32 - Dev C++ v4.9.9.1 (h)"
strings:
    	$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 ?? ?? 00 00 90 90 90 90 90 90 90 }

condition:
    	$a0 at manape.ep
}

    
rule Borland_Delphi_5____Portions_Copyright__c__1983_99_Borland__h_
{
meta:
    description = "Borland Delphi 5 -> Portions Copyright (c) 1983,99 Borland (h)"
strings:
    	$a0 = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 39 20 42 6F 72 6C 61 6E 64 00 }

condition:
    	$a0
}

    
rule Nullsoft_Install_System_v1_98
{
meta:
    description = "Nullsoft Install System v1.98"
strings:
    	$a0 = { 83 EC 0C 53 56 57 FF 15 2C 81 40 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C___5_0___7_1
{
meta:
    description = "Microsoft Visual C++ 5.0 - 7.1"
strings:
    	$a0 = { 55 8B EC 81 EC 04 01 00 00 68 04 01 00 00 8D 85 FC FE FF FF 50 6A 00 FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 8D FC FE FF FF 51 E8 ?? ?? ?? ?? 83 C4 04 E8 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 8B E5 5D C2 10 00 }

condition:
    	$a0
}

    
rule LCC_Win32_v1_x
{
meta:
    description = "LCC Win32 v1.x"
strings:
    	$a0 = { 64 A1 ?? ?? ?? ?? 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 9A 10 40 ?? 50 }

condition:
    	$a0 at manape.ep
}

    
rule MinGW_GCC_2_x
{
meta:
    description = "MinGW GCC 2.x"
strings:
    	$a0 = { 55 89 E5 ?? ?? ?? ?? ?? ?? FF FF ?? ?? ?? ?? ?? 00 ?? ?? 00 ?? ?? ?? 00 00 00 00 }

condition:
    	$a0 at manape.ep
}

    
rule MinGW_v3_2_x___mainCRTStartup_
{
meta:
    description = "MinGW v3.2.x (_mainCRTStartup)"
strings:
    	$a0 = { 55 89 E5 83 EC 08 6A 00 6A 00 6A 00 6A 00 E8 0D 00 00 00 B8 00 00 00 00 C9 C3 90 90 90 90 90 90 FF 25 38 20 40 00 90 90 00 00 00 00 00 00 00 00 FF FF FF FF 00 00 00 00 FF FF FF FF 00 00 00 00 00 }

condition:
    	$a0 at manape.ep
}

    
rule PureBasic_4_x_DLL____Neil_Hodgson
{
meta:
    description = "PureBasic 4.x DLL -> Neil Hodgson"
strings:
    	$a0 = { 83 7C 24 08 01 75 0E 8B 44 24 04 A3 ?? ?? ?? 10 E8 22 00 00 00 83 7C 24 08 02 75 00 83 7C 24 08 00 75 05 E8 ?? 00 00 00 83 7C 24 08 03 75 00 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? 0F 00 00 A3 }

condition:
    	$a0 at manape.ep
}

    
rule Free_Pascal_v0_99_10
{
meta:
    description = "Free Pascal v0.99.10"
strings:
    	$a0 = { E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29 }

condition:
    	$a0 at manape.ep
}

    
rule MASM_TASM___sig2_h_
{
meta:
    description = "MASM/TASM - sig2(h)"
strings:
    	$a0 = { C2 ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 }

condition:
    	$a0
}

    
rule Nullsoft_Install_System_2_0_RC2
{
meta:
    description = "Nullsoft Install System 2.0 RC2"
strings:
    	$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }

condition:
    	$a0
}

    
rule Nullsoft_Install_System_v2_0_RC2
{
meta:
    description = "Nullsoft Install System v2.0 RC2"
strings:
    	$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 68 68 92 40 00 56 FF D3 E8 6A FF FF FF 85 C0 0F 84 59 01 00 00 BE 20 E4 42 00 56 FF 15 68 70 40 00 68 5C 92 40 00 56 E8 B9 28 00 00 57 FF 15 BC 70 40 00 BE 00 40 43 00 50 56 FF 15 B8 70 40 00 6A 00 FF 15 44 71 40 00 80 3D 00 40 43 00 22 A3 20 EC 42 00 8B C6 75 0A C6 44 24 13 22 B8 01 40 43 00 8B 3D 18 72 40 00 EB 09 3A 4C 24 13 74 09 50 FF D7 8A 08 84 C9 75 F1 50 FF D7 8B F0 89 74 24 1C EB 05 56 FF D7 8B F0 80 3E 20 74 F6 80 3E 2F 75 44 46 80 3E 53 75 0C 8A 46 01 0C 20 3C 20 75 03 83 CD 02 81 3E 4E 43 52 }
	$a1 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }

condition:
    	$a0 or $a1
}

    
rule Microsoft_Visual_C_v2_0
{
meta:
    description = "Microsoft Visual C v2.0"
strings:
    	$a0 = { 53 56 57 BB ?? ?? ?? ?? 8B ?? ?? ?? 55 3B FB 75 }

condition:
    	$a0 at manape.ep
}

    
rule MASM___TASM
{
meta:
    description = "MASM / TASM"
strings:
    	$a0 = { 6A 00 E8 ?? ?? 00 00 A3 ?? 32 40 00 E8 ?? ?? 00 00 }
	$a1 = { 6A 00 E8 ?? 0? 00 00 A3 ?? ?? 40 00 ?? ?? ?? ?0 ?0 ?? ?? 00 00 00 ?? ?? 0? ?? ?? ?0 ?? ?? ?0 ?0 ?? ?? ?? ?0 ?? 0? ?? ?0 ?0 00 }
	$a2 = { 6A 00 E8 ?? ?? 00 00 A3 ?? 32 40 00 E8 ?? ?? 00 00 }
	$a3 = { 6A 00 E8 ?? 0? 00 00 A3 ?? 32 40 00 E8 ?? 0? 00 00 }

condition:
    	$a0 or $a1 or $a2 at manape.ep or $a3 at manape.ep
}

    
rule Wise_Installer_Stub
{
meta:
    description = "Wise Installer Stub"
strings:
    	$a0 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF }
	$a1 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 75 09 47 80 3F 20 74 FA 89 7D ?? 53 FF 15 ?? 40 40 00 80 3F 2F 89 45 ?? 75 ?? 8A 47 01 3C 53 74 04 3C 73 75 06 89 35 }
	$a2 = { 55 8B EC 81 EC ?? ?? 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 }
	$a3 = { 55 8B EC 81 EC ?? 04 00 00 53 56 57 6A ?? ?? ?? ?? ?? ?? ?? FF 15 ?? ?? 40 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 ?? 20 }
	$a4 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF 89 45 FC 0F 84 7B 01 00 00 8D 85 90 FC FF FF 50 56 FF 15 28 20 40 00 8D 85 98 FE FF FF 50 53 8D 85 90 FC FF FF 68 10 30 40 00 50 FF 15 24 20 40 00 53 68 80 00 00 00 6A 02 53 53 8D 85 98 FE FF FF 68 00 00 00 40 50 FF D7 83 F8 FF 89 45 F4 0F 84 2F 01 00 00 53 53 53 6A 02 53 FF 75 FC FF 15 00 20 40 00 53 53 53 6A 04 50 89 45 F8 FF 15 1C 20 40 00 8B F8 C7 45 FC 01 00 00 00 8D 47 01 8B 08 81 F9 4D 5A 9A 00 74 08 81 F9 4D 5A 90 00 75 06 80 78 04 03 74 0D FF 45 FC 40 81 7D FC 00 80 00 00 7C DB 8D 4D F0 53 51 68 }

condition:
    	$a0 at manape.ep or $a1 or $a2 or $a3 at manape.ep or $a4 at manape.ep
}

    
rule Borland_C___Borland_Builder
{
meta:
    description = "Borland C / Borland Builder"
strings:
    	$a0 = { 3B CF 76 05 2B CF FC F3 AA 59 }

condition:
    	$a0
}

    
rule Gentee_Installer_Custom
{
meta:
    description = "Gentee Installer Custom"
strings:
    	$a0 = { 55 8B EC 81 EC 14 04 00 00 53 56 57 6A 00 FF 15 08 41 40 00 68 00 50 40 00 FF 15 04 41 40 00 85 C0 74 29 6A 00 A1 00 20 40 00 ?? ?? ?? ?? 41 40 00 8B F0 6A 06 56 FF 15 1C 41 40 00 6A 03 56 FF }

condition:
    	$a0 at manape.ep
}

    
rule Cygwin32
{
meta:
    description = "Cygwin32"
strings:
    	$a0 = { 55 89 E5 83 EC 04 83 3D }

condition:
    	$a0 at manape.ep
}

    
rule MetaWare_High_C___Phar_Lap_DOS_Extender_1983_89
{
meta:
    description = "MetaWare High C + Phar Lap DOS Extender 1983-89"
strings:
    	$a0 = { B8 ?? ?? 8E D8 B8 ?? ?? CD 21 A3 ?? ?? 3C 03 7D ?? B4 09 }

condition:
    	$a0 at manape.ep
}

    
rule Netopsystems_FEAD_Optimizer
{
meta:
    description = "Netopsystems FEAD Optimizer"
strings:
    	$a0 = { 60 BE 00 50 43 00 8D BE 00 C0 FC FF }
	$a1 = { E8 00 00 00 00 58 BB 00 00 40 00 8B }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule _NET_DLL____Microsoft
{
meta:
    description = ".NET DLL -> Microsoft"
strings:
    	$a0 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 44 6C 6C 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 ?? 00 00 FF 25 }

condition:
    	$a0
}

    
rule MS_Run_Time_Library_1988__04_
{
meta:
    description = "MS Run-Time Library 1988 (04)"
strings:
    	$a0 = { 1E B8 ?? ?? 8E D8 B4 30 CD 21 3C 02 73 ?? BA ?? ?? E8 ?? ?? 06 33 C0 50 CB }

condition:
    	$a0 at manape.ep
}

    
rule Setup2Go_Installer_Stub
{
meta:
    description = "Setup2Go Installer Stub"
strings:
    	$a0 = { 5B 53 45 54 55 50 5F 49 4E 46 4F 5D 0D 0A 56 65 72 }

condition:
    	$a0
}

    
rule Microsoft_C_Library_1985
{
meta:
    description = "Microsoft C Library 1985"
strings:
    	$a0 = { BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7 81 C4 ?? ?? FB 73 }

condition:
    	$a0 at manape.ep
}

    
rule FreePascal_2_0_0_Win32_____B__rczi_G__bor__Pierre_Muller___Peter_Vreman_
{
meta:
    description = "FreePascal 2.0.0 Win32 -> (Bérczi Gábor, Pierre Muller & Peter Vreman)"
strings:
    	$a0 = { C6 05 00 80 40 00 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 }
	$a1 = { C6 05 ?? ?? ?? ?? 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 }
	$a2 = { C6 05 00 80 40 00 01 E8 74 00 00 00 C6 05 00 80 40 00 00 E8 68 00 00 00 50 E8 00 00 00 00 FF 25 D8 A1 40 00 90 90 90 90 90 90 90 90 90 90 90 90 55 89 E5 83 EC 04 89 5D FC E8 92 00 00 00 E8 ED 00 00 00 89 C3 B9 ?? 70 40 00 89 DA B8 00 00 00 00 E8 0A 01 00 00 E8 C5 01 00 00 89 D8 E8 3E 02 00 00 E8 B9 01 00 00 E8 54 02 00 00 8B 5D FC C9 C3 8D 76 00 00 00 00 00 00 00 00 00 00 00 00 00 55 89 E5 C6 05 10 80 40 00 00 E8 D1 03 00 00 6A 00 64 FF 35 00 00 00 00 89 E0 A3 ?? 70 40 00 55 31 ED 89 E0 A3 20 80 40 00 66 8C D5 89 2D 30 80 40 00 E8 B9 03 00 00 31 ED E8 72 FF FF FF 5D E8 BC 03 00 00 C9 C3 00 00 00 00 00 00 00 00 00 00 55 89 E5 83 EC 08 E8 15 04 00 00 A1 ?? 70 40 00 89 45 F8 B8 01 00 00 00 89 45 FC 3B 45 F8 7F 2A FF 4D FC 90 FF 45 FC 8B 45 FC 83 3C C5 ?? 70 40 00 00 74 09 8B 04 C5 ?? 70 40 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep or $a2 at manape.ep
}

    
rule Nullsoft_Install_System_1_xx
{
meta:
    description = "Nullsoft Install System 1.xx"
strings:
    	$a0 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 }
	$a1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 }

condition:
    	$a0 at manape.ep or $a1
}

    
rule WinZip_32_bit_SFX_v8_x_module
{
meta:
    description = "WinZip 32-bit SFX v8.x module"
strings:
    	$a0 = { 53 FF 15 ?? ?? ?? 00 B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 74 01 40 ?? ?? ?? ?? FF 15 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_Basic_v5_0___v6_0
{
meta:
    description = "Microsoft Visual Basic v5.0 - v6.0"
strings:
    	$a0 = { 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 ?? 00 00 00 30 ?? 00 }
	$a1 = { FF 25 ?? ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF }

condition:
    	$a0 or $a1
}

    
rule LaunchAnywhere_v4_0_0_1
{
meta:
    description = "LaunchAnywhere v4.0.0.1"
strings:
    	$a0 = { 55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 E0 3E 42 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 C0 69 44 00 E8 E4 80 FF FF 59 E8 4E 29 00 00 E8 C9 0D 00 00 85 C0 75 08 6A FF E8 6E 2B 00 00 59 E8 A8 2C 00 00 E8 23 2E 00 00 FF 15 4C C2 44 00 89 C3 }
	$a1 = { 55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 E0 3E 42 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 C0 69 44 00 E8 E4 80 FF FF 59 E8 4E 29 00 00 E8 C9 0D 00 00 85 C0 75 08 6A FF E8 6E 2B 00 00 59 E8 A8 2C 00 00 E8 23 2E 00 00 FF 15 4C C2 44 00 89 C3 EB 19 3C 22 75 14 89 C0 8D 40 00 43 8A 03 84 C0 74 04 3C 22 75 F5 3C 22 75 01 43 8A 03 84 C0 74 0B 3C 20 74 07 3C 09 75 D9 EB 01 43 8A 03 84 C0 74 04 3C 20 7E F5 8D 45 B8 50 FF 15 E4 C1 44 00 8B 45 E4 25 01 00 00 00 74 06 0F B7 45 E8 EB 05 B8 0A 00 00 00 50 53 6A 00 6A 00 FF 15 08 C2 44 00 50 E8 63 15 FF FF 50 E8 EE 2A 00 00 59 8D 65 FC 5B }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Microsoft_Visual_C_5_0
{
meta:
    description = "Microsoft Visual C 5.0"
strings:
    	$a0 = { 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 A8 53 56 57 }

condition:
    	$a0
}

    
rule Microsoft_Visual_C___v7_1_DLL__Debug_
{
meta:
    description = "Microsoft Visual C++ v7.1 DLL (Debug)"
strings:
    	$a0 = { 55 8B EC ?? ?? 0C 83 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 8B }

condition:
    	$a0 at manape.ep
}

    
rule Turbo_Pascal_v3_0_1985
{
meta:
    description = "Turbo Pascal v3.0 1985"
strings:
    	$a0 = { 90 90 CD AB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 35 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_Basic_v6_0_DLL
{
meta:
    description = "Microsoft Visual Basic v6.0 DLL"
strings:
    	$a0 = { 5A 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 52 E9 ?? ?? FF }

condition:
    	$a0 at manape.ep
}

    
rule InstallAnywhere_6_1____Zero_G_Software_Inc
{
meta:
    description = "InstallAnywhere 6.1 -> Zero G Software Inc"
strings:
    	$a0 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }
	$a1 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }
	$a2 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep or $a2 at manape.ep
}

    
rule Metrowerks_CodeWarrior_v2_0__GUI_
{
meta:
    description = "Metrowerks CodeWarrior v2.0 (GUI)"
strings:
    	$a0 = { 55 89 E5 53 56 83 EC 44 55 B8 FF FF FF FF 50 50 68 ?? ?? 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? 00 00 E8 ?? ?? 00 00 E8 }

condition:
    	$a0
}

    
rule MASM_TASM___sig1_h_
{
meta:
    description = "MASM/TASM - sig1(h)"
strings:
    	$a0 = { CC FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 FF 25 ?? ?? ?? 00 }

condition:
    	$a0
}

    
rule Nullsoft_Install_System_2_0a0
{
meta:
    description = "Nullsoft Install System 2.0a0"
strings:
    	$a0 = { 83 EC 0C 53 56 57 FF 15 B4 10 40 00 05 E8 03 00 00 BE E0 E3 41 00 89 44 24 10 B3 20 FF 15 28 10 40 00 68 00 04 00 00 FF 15 14 11 40 00 50 56 FF 15 10 11 40 00 80 3D E0 E3 41 00 22 75 08 80 C3 02 BE E1 E3 41 00 8A 06 8B 3D 14 12 40 00 84 C0 74 19 3A C3 74 }

condition:
    	$a0
}

    
rule Microsoft_Visual_C__
{
meta:
    description = "Microsoft Visual C++"
strings:
    	$a0 = { 8B 44 24 08 83 ?? ?? 74 }
	$a1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 }
	$a2 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 }
	$a3 = { 8B 44 24 08 56 83 E8 ?? 74 ?? 48 75 }

condition:
    	$a0 at manape.ep or $a1 or $a2 at manape.ep or $a3 at manape.ep
}

    
rule Borland_Delphi_v6_0
{
meta:
    description = "Borland Delphi v6.0"
strings:
    	$a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 45 00 E8 ?? ?? ?? FF A1 ?? ?? 45 00 8B 00 E8 ?? ?? FF FF 8B 0D }
	$a1 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? FF A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? E8 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Microsoft_Visual_C___v6_0
{
meta:
    description = "Microsoft Visual C++ v6.0"
strings:
    	$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC ?? 53 56 57 }
	$a1 = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57 89 65 E8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? FF }
	$a2 = { 55 8B EC 83 EC 50 53 56 57 BE ?? ?? ?? ?? 8D 7D F4 A5 A5 66 A5 8B }

condition:
    	$a0 or $a1 or $a2 at manape.ep
}

    
rule Borland_Delphi_3____Portions_Copyright__c__1983_96_Borland__h_
{
meta:
    description = "Borland Delphi 3 -> Portions Copyright (c) 1983,96 Borland (h)"
strings:
    	$a0 = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 36 20 42 6F 72 6C 61 6E 64 00 }

condition:
    	$a0
}

    
rule Microsoft_Visual_C___v4_x
{
meta:
    description = "Microsoft Visual C++ v4.x"
strings:
    	$a0 = { 64 A1 00 00 00 00 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 64 89 25 00 00 00 00 83 EC ?? 53 56 57 }

condition:
    	$a0 at manape.ep
}

    
rule _NET_executable____Microsoft
{
meta:
    description = ".NET executable -> Microsoft"
strings:
    	$a0 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 00 00 00 FF 25 }

condition:
    	$a0
}

    
rule Microsoft_Visual_C____3_0_old_crap_
{
meta:
    description = "Microsoft Visual C++ (3.0 old crap)"
strings:
    	$a0 = { 64 A1 00 00 00 00 55 ?? ?? 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 ?? ?? ?? ?? ?? 00 00 83 EC 10 }

condition:
    	$a0 at manape.ep
}

    
rule Borland_C___for_Win32_1999
{
meta:
    description = "Borland C++ for Win32 1999"
strings:
    	$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 }
	$a1 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 ?? ?? ?? ?? A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 52 }

condition:
    	$a0 or $a1 at manape.ep
}

    
rule MinGW_3_2_x__WinMain_
{
meta:
    description = "MinGW 3.2.x (WinMain)"
strings:
    	$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 FC 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 FC 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 18 41 40 00 89 EC 5D }

condition:
    	$a0
}

    
rule Microsoft_Visual_C___8_0__MFC_
{
meta:
    description = "Microsoft Visual C++ 8.0 (MFC)"
strings:
    	$a0 = { 48 83 EC 28 E8 ?? ?? 00 00 48 83 C4 28 E9 0E FD FF FF CC CC CC CC CC CC CC CC CC CC CC CC CC CC }

condition:
    	$a0 at manape.ep
}

    
rule MS_FORTRAN_Library_19__
{
meta:
    description = "MS FORTRAN Library 19??"
strings:
    	$a0 = { FC 1E B8 ?? ?? 8E D8 9A ?? ?? ?? ?? 81 ?? ?? ?? 8B EC B8 ?? ?? 8E C0 26 C7 ?? ?? ?? ?? ?? 26 }
	$a1 = { FC 1E B8 ?? ?? 8E D8 9A ?? ?? ?? ?? 81 ?? ?? ?? 8B EC 8C DB 8E C3 BB ?? ?? 9A ?? ?? ?? ?? 9B DB E3 9B D9 2E ?? ?? 33 C9 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule CreateInstall_2003_3_5
{
meta:
    description = "CreateInstall 2003.3.5"
strings:
    	$a0 = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 FF 15 E4 80 40 }

condition:
    	$a0
}

    
rule Microsoft_Visual_Basic_v6_0
{
meta:
    description = "Microsoft Visual Basic v6.0"
strings:
    	$a0 = { FF 25 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? FF FF FF ?? ?? ?? ?? ?? ?? 30 }

condition:
    	$a0
}

    
rule Borland_Delphi_DLL
{
meta:
    description = "Borland Delphi DLL"
strings:
    	$a0 = { 55 8B EC 83 C4 B4 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 40 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C___v6_0__Debug_Version_
{
meta:
    description = "Microsoft Visual C++ v6.0 (Debug Version)"
strings:
    	$a0 = { 55 8B EC 51 ?? ?? ?? 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 }

condition:
    	$a0 at manape.ep
}

    
rule MS_Visual_C___v_8_DLL__h_small_sig2_
{
meta:
    description = "MS Visual C++ v.8 DLL (h-small sig2)"
strings:
    	$a0 = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 0F 84 ?? ?? 00 00 83 FE 01 }

condition:
    	$a0 at manape.ep
}

    
rule PerlApp_6_0_2____ActiveState
{
meta:
    description = "PerlApp 6.0.2 -> ActiveState"
strings:
    	$a0 = { 68 2C EA 40 00 FF D3 83 C4 0C 85 C0 0F 85 CD 00 00 00 6A 09 57 68 20 EA 40 00 FF D3 83 C4 0C 85 C0 75 12 8D 47 09 50 FF 15 1C D1 40 00 59 A3 B8 07 41 00 EB 55 6A 08 57 68 14 EA 40 00 FF D3 83 C4 0C 85 C0 75 11 8D 47 08 50 FF 15 1C D1 40 00 59 89 44 24 10 EB 33 6A 09 57 68 08 EA 40 00 FF D3 83 C4 0C 85 C0 74 22 6A 08 57 68 FC E9 40 00 FF D3 83 C4 0C 85 C0 74 11 6A 0B 57 68 F0 E9 40 00 FF D3 83 C4 0C 85 C0 75 55 }
	$a1 = { 68 9C E1 40 00 FF 15 A4 D0 40 00 85 C0 59 74 0F 50 FF 15 1C D1 40 00 85 C0 59 89 45 FC 75 62 6A 00 8D 45 F8 FF 75 0C F6 45 14 01 50 8D 45 14 50 E8 9B 01 00 00 83 C4 10 85 C0 0F 84 E9 00 00 00 8B 45 F8 83 C0 14 50 FF D6 85 C0 59 89 45 FC 75 0E FF 75 14 FF 15 78 D0 40 00 E9 C9 00 00 00 68 8C E1 40 00 FF 75 14 50 }

condition:
    	$a0 or $a1
}

    
rule Nullsoft_PiMP_Install_System_1_x
{
meta:
    description = "Nullsoft PiMP Install System 1.x"
strings:
    	$a0 = { 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05 E8 03 00 00 BE ?? ?? ?? 00 89 44 24 10 B3 20 FF 15 28 ?? 40 00 68 00 04 00 00 FF 15 ?? ?? 40 00 50 56 FF 15 ?? ?? 40 00 80 3D ?? ?? ?? 00 22 75 08 80 C3 02 BE ?? ?? ?? 00 8A 06 8B 3D ?? ?? 40 00 84 C0 74 ?? 3A C3 74 }

condition:
    	$a0
}

    
rule Microsoft__R__Incremental_Linker_Version_5_12_8078__MASM_TASM_
{
meta:
    description = "Microsoft (R) Incremental Linker Version 5.12.8078 (MASM/TASM)"
strings:
    	$a0 = { 6A 00 68 00 30 40 00 68 1E 30 40 00 6A 00 E8 0D 00 00 00 6A 00 E8 00 00 00 00 FF 25 00 20 40 00 FF 25 08 20 40 }

condition:
    	$a0
}

    
rule Microsoft_Visual_C___v5_0_v6_0__MFC_
{
meta:
    description = "Microsoft Visual C++ v5.0/v6.0 (MFC)"
strings:
    	$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 }

condition:
    	$a0 at manape.ep
}

    
rule Free_Pascal_v1_0_10__win32_console_
{
meta:
    description = "Free Pascal v1.0.10 (win32 console)"
strings:
    	$a0 = { C6 05 ?? ?? ?? 00 01 E8 ?? ?? 00 00 C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 ?? EC }

condition:
    	$a0
}

    
rule Microsoft_C
{
meta:
    description = "Microsoft C"
strings:
    	$a0 = { B4 30 CD 21 3C 02 73 ?? B8 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_Visual_C___v7_0_DLL
{
meta:
    description = "Microsoft Visual C++ v7.0 DLL"
strings:
    	$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 ?? ?? 83 }
	$a1 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 }

condition:
    	$a0 or $a1 at manape.ep
}

    
rule Borland_Delphi_v4_0___v5_0
{
meta:
    description = "Borland Delphi v4.0 - v5.0"
strings:
    	$a0 = { 50 6A 00 E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }
	$a1 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 ?? ?? ?? ?? C7 42 0C ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }

condition:
    	$a0 at manape.ep or $a1 at manape.ep
}

    
rule Microsoft_Visual_C___v7_1_DLL
{
meta:
    description = "Microsoft Visual C++ v7.1 DLL"
strings:
    	$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 75 09 83 3D ?? ?? 40 00 00 EB 26 83 FE 01 74 05 83 FE 02 75 22 A1 }
	$a1 = { 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 40 89 45 E4 }
	$a2 = { 83 7C 24 08 01 75 ?? ?? ?? 24 04 50 A3 ?? ?? ?? 50 FF 15 00 10 ?? 50 33 C0 40 C2 0C 00 }
	$a3 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 C4 E4 53 56 57 89 65 E8 C7 45 E4 01 00 00 00 C7 45 FC }

condition:
    	$a0 at manape.ep or $a1 at manape.ep or $a2 at manape.ep or $a3 at manape.ep
}

    
rule MinGW_3_2_x__main_
{
meta:
    description = "MinGW 3.2.x (main)"
strings:
    	$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 E4 40 40 00 E8 68 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 E4 40 40 00 E8 48 00 00 00 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 55 08 89 14 24 FF 15 00 41 40 00 89 EC 5D }

condition:
    	$a0
}

    
rule MingWin32___Dev_C___v4_x__h_
{
meta:
    description = "MingWin32 - Dev C++ v4.x (h)"
strings:
    	$a0 = { 55 89 E5 83 EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 55 89 E5 83 EC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 55 ?? ?? ?? ?? ?? ?? ?? ?? ?? FF ?? ?? ?? ?? 00 }

condition:
    	$a0 at manape.ep
}


    
rule Borland_C___1994
{
meta:
    description = "Borland C++ 1994"
strings:
    	$a0 = { 8C CA 2E 89 ?? ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B 1E ?? ?? 8E DA A3 ?? ?? 8C }

condition:
    	$a0 at manape.ep
}

    
rule Borland_C___1991
{
meta:
    description = "Borland C++ 1991"
strings:
    	$a0 = { 2E 8C 06 ?? ?? 2E 8C 1E ?? ?? BB ?? ?? 8E DB 1E E8 ?? ?? 1F }

condition:
    	$a0 at manape.ep
}

    
rule Nullsoft_Install_System_v2_0b2__v2_0b3
{
meta:
    description = "Nullsoft Install System v2.0b2, v2.0b3"
strings:
    	$a0 = { 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 ?? ?? ?? 00 57 FF 15 ?? ?? 40 00 57 FF 15 }

condition:
    	$a0 at manape.ep
}

    
rule Inno_Setup_Module_v1_2_9
{
meta:
    description = "Inno Setup Module v1.2.9"
strings:
    	$a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8 E0 }

condition:
    	$a0 at manape.ep
}

    
rule Microsoft_FORTRAN
{
meta:
    description = "Microsoft FORTRAN"
strings:
    	$a0 = { FC 1E B8 ?? ?? 8E D8 9A ?? ?? ?? ?? 81 ?? ?? ?? 8B EC 8C DB 8E C3 BB ?? ?? B9 ?? ?? 9A ?? ?? ?? ?? 80 ?? ?? ?? ?? 74 ?? E9 }

condition:
    	$a0 at manape.ep
}



    
rule MSVC___v_8__procedure_1_recognized___h_
{
meta:
    description = "MSVC++ v.8 (procedure 1 recognized - h)"
strings:
    	$a0 = { 55 8B EC 83 EC 10 A1 ?? ?? ?? ?? 83 65 F8 00 83 65 FC 00 53 57 BF 4E E6 40 BB 3B C7 BB 00 00 FF FF 74 0D 85 C3 74 09 F7 D0 A3 ?? ?? ?? ?? EB 60 56 8D 45 F8 50 FF 15 ?? ?? ?? ?? 8B 75 FC 33 75 F8 FF 15 ?? ?? ?? ?? 33 F0 FF 15 ?? ?? ?? ?? 33 F0 FF 15 ?? ?? ?? ?? 33 F0 8D 45 F0 50 FF 15 ?? ?? ?? ?? 8B 45 F4 33 45 F0 33 F0 3B F7 75 07 BE 4F E6 40 BB EB 0B 85 F3 75 07 8B C6 C1 E0 10 0B F0 89 35 ?? ?? ?? ?? F7 D6 89 35 ?? ?? ?? ?? 5E 5F 5B C9 C3 }

condition:
    	$a0
}
