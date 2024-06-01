#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#define _CRT_SECURE_NO_WARNINGS
//make here your payload  

unsigned char pshellcode[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8,
0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51 };

char* GenerateIpv4(int a, int b, int c, int d) {
    // Allouer dynamiquement de la mémoire pour la chaîne de sortie
    char* Output = (char*)malloc(32 * sizeof(char));
    //see if the allocaion are success 
    if (Output == NULL) {
        return NULL;
    }

    // Créer l'adresse IPv4 et l'enregistrer dans la variable 'Output'
    sprintf_s(Output, 32, "%d.%d.%d.%d", a, b, c, d);

    return Output;
}

BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
    // we see if the payload is a multiple of 4 ,if not we need to complete it  with 0 to make it a multiple of 4
    if (pShellcode == NULL || ShellcodeSize == 0 || ShellcodeSize % 4 != 0) {
        return FALSE;
    }
    printf("char* Ipv4Array[%d] = {\n\t", (int)(ShellcodeSize / 4));

    int counter = 0;

    for (int i = 0; i < ShellcodeSize; i += 4) {
        counter++;

        char* IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);

        if (IP == NULL) {
            printf("Memory allocation error\n");
            return FALSE;
        }

        if (i >= ShellcodeSize - 4) {
            printf("\"%s\"", IP);
        }
        else {
            printf("\"%s\", ", IP);
        }

        free(IP);

        if (counter % 8 == 0) {
            printf("\n\t");
        }
    }
    printf("\n};\n\n");
    return TRUE;
}

int main() {
    SIZE_T ShellcodeSize = sizeof(pshellcode);
    printf("le shellcode du payload est %d\n",ShellcodeSize);

    printf("let's start using this method\n");
    if (GenerateIpv4Output(pshellcode, ShellcodeSize)) {
        printf("tu va bien \n");
        return 1;
    }
    printf("error ");
    return 0;
}
