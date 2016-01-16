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