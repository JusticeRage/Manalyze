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

#include <Windows.h>
#include <iostream>

int main(int argc, char** argv)
{	
	// Vanilla injection imports
	OpenProcess(0, 0, 0);
	CreateRemoteThread(0, 0, 0, 0, 0, 0, 0);
	WriteProcessMemory(0, 0, 0, 0, 0);

	std::cout << "cmd.exe" << std::endl;
	// EICAR antivirus signature. ClamAV's rules only detect the standard signature at offset 0, but somehow has a rule
	// for the base64-encoded string.
	std::cout << "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n"; 
	std::cout << std::hex;
}