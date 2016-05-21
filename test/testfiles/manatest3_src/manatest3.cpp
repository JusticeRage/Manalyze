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

/*
	This test file is a 64bit PE with a delay-loaded DLL and a TLS callback.
	To compile, add "/DelayLoad:AdvApi32.dll" to the linker flags.
*/

#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <dshow.h>

#pragma comment(lib, "DelayImp.lib")

void WINAPI tls_cb(PVOID Module, DWORD Reason, PVOID Context)
{
	wprintf(L"Code executed in the TLS callback.\n");
}

// Source of the TLS_Callback code: https://stackoverflow.com/questions/14538159/about-tls-callback-in-windows
#ifdef _WIN64
    #pragma const_seg(".CRT$XLF")
    EXTERN_C const
#else
    #pragma data_seg(".CRT$XLF")
    EXTERN_C
#endif
PIMAGE_TLS_CALLBACK p_tls_cb = tls_cb;
#ifdef _WIN64
    #pragma const_seg()
#else
    #pragma data_seg()
#endif

#ifdef _WIN64
     #pragma comment (linker, "/INCLUDE:_tls_used")
     #pragma comment (linker, "/INCLUDE:p_tls_cb")
#else
     #pragma comment (linker, "/INCLUDE:__tls_used")
     #pragma comment (linker, "/INCLUDE:p_tls_cb")
#endif

int main(int argc, char** argv)
{
	wprintf(L"Now running main().\n");
	HCRYPTPROV hCryptProv = NULL;
	LPWSTR UserName = L"MyKeyContainer";

	if (CryptAcquireContext(
		&hCryptProv,               // handle to the CSP
		UserName,                  // container name 
		nullptr,                   // use the default provider
		PROV_RSA_FULL,             // provider type
		0))                        // flag values
	{
		wprintf(L"A cryptographic context with the %s key container has been acquired.\n",UserName);
	}
}
