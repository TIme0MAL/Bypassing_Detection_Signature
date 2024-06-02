#include <stdio.h>
#include <Windows.h>
#include <stdlib.h> // Pour malloc
#define _CRT_SECURE_NO_WARNINGS

char* MacArray[2] = {
		"FC-48-83-E4-F0-E8", "C0-00-00-00-41-51"
};

typedef NTSTATUS(NTAPI* fnRtlEthernetStringToAddressA)(
	PCSTR		S,
	PCSTR* Terminator,
	PVOID		Addr
	);

BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE          pBuffer = NULL,
		TmpBuffer = NULL;

	SIZE_T         sBuffSize = NULL;

	PCSTR          Terminator = NULL;

	NTSTATUS       STATUS = NULL;

	// Getting RtlIpv6StringToAddressA address from ntdll.dll
	fnRtlEthernetStringToAddressA pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlEthernetStringToAddressA");
	if (pRtlEthernetStringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of MAC addresses * 6
	sBuffSize = NmbrOfElements * 6;


	// Allocating memeory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	// Loop through all the MAC addresses saved in MacArray
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one MAC address at a time
		// MacArray[i] is a single Mac address from the array MacArray
		if ((STATUS = pRtlEthernetStringToAddressA(MacArray[i], &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlEthernetStringToAddressA Failed At [%s] With Error 0x%0.8X", MacArray[i], STATUS);
			return FALSE;
		}

		// 6 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 6 to store the
		TmpBuffer = (PBYTE)(TmpBuffer + 6);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress = pBuffer;
	*pDSize = sBuffSize;

	return TRUE;

}

int main() {
	SIZE_T ShellcodeSize = sizeof(MacArray)/sizeof(MacArray[0]);
	PBYTE ppDAddress = NULL;
	SIZE_T* pDSize = 0;
	//pour savoir le taille du tableau
	printf("le size de tout le tableau est %d\n", sizeof(MacArray));
	//pour savoir la taille de element du tableau
	printf("le size d'un element du tableau est %d\n", sizeof(MacArray[0]));
	//pour savoir le nombre des elements qui existe dans le tableau
	printf("le shellcode du payload est de taille %d\n", ShellcodeSize); 
	printf("let's start using this method\n");

	if  (MacDeobfuscation(MacArray,ShellcodeSize,&ppDAddress,&pDSize)) {
		printf("tu va bien \n");
		for (int i = 0; i < pDSize; i++) {
			printf("0x%02X,", ppDAddress[i]);
		}
		printf("\n");
		//on a puisse de liberer cette memoire car on allouer dynamiquement si ce n'est pas le cas on peut pas 

		HeapFree(GetProcessHeap(), 0, ppDAddress);
		

		// Free the allocated memory after use
		return 0;
	}

	printf("error ");
	return 1;
}