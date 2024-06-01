#include <stdio.h>
#include <Windows.h>
#include <stdlib.h> // Pour malloc
#define _CRT_SECURE_NO_WARNINGS

unsigned char pshellcode[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8,
0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,0x41, 0x50, 0x52, 0x51 };
// Function takes in 4 raw bytes and returns them in an IPv4 string format
// Function takes in 16 raw bytes and returns them in an IPv6 address string format
char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	// Each IPv6 segment is 32 bytes
	char* Output0 = (char*)malloc(32 * sizeof(char));
	char* Output1 = (char*)malloc(32 * sizeof(char));
	char* Output2 = (char*)malloc(32 * sizeof(char));
	char* Output3 = (char*)malloc(32 * sizeof(char));
	// There are 4 segments in an IPv6 (32 * 4 = 128)
	char* result = (char*)malloc(128 * sizeof(char));
	if (Output0 == NULL || Output1 == NULL || Output2 == NULL || Output3 == NULL || result == NULL) {
		// Gérer l'échec de l'allocation
		// Par exemple, libérer la mémoire allouée précédemment et retourner NULL
		free(Output0);
		free(Output1);
		free(Output2);
		free(Output3);
		free(result);
		return NULL;
	}


		// Generating output0 using the first 4 bytes
	sprintf_s(Output0, 32, "%0.2X%0.2X:%0.2X%0.2X", a, b, c, d);

	// Generating output1 using the second 4 bytes
	sprintf_s(Output1, 32, "%0.2X%0.2X:%0.2X%0.2X", e, f, g, h);

	// Generating output2 using the third 4 bytes
	sprintf_s(Output2, 32, "%0.2X%0.2X:%0.2X%0.2X", i, j, k, l);

	// Generating output3 using the last 4 bytes
	sprintf_s(Output3, 32, "%0.2X%0.2X:%0.2X%0.2X", m, n, o, p);

	// Combining Output0,1,2,3 to generate the IPv6 address
	sprintf_s(result, 128, "%s:%s:%s:%s", Output0, Output1, Output2, Output3);

	// Optional: Print the 'result' variable to the console
	// printf("[i] result: %s\n", (char*)result);

	return result;
}


// Generate the IPv6 output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	// If the shellcode buffer is null or the size is not a multiple of 16, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0) {
		return FALSE;
	}
	printf("char* Ipv6Array [%d] = { \n\t", (int)(ShellcodeSize / 16));

	// We will read one shellcode byte at a time, when the total is 16, begin generating the IPv6 address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 16.
	int c = 16, counter = 0;
	char* IP = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {
		// Track the number of bytes read and when they reach 16 we enter this if statement to begin generating the IPv6 address
		if (c == 16) {
			counter++;
			// Generating the IPv6 address from 16 bytes which begin at i until [i + 15]
			IP = GenerateIpv6(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);

			if (i == ShellcodeSize - 16) {

				// Printing the last IPv6 address
				printf("\"%s\"", IP);
				break;
			}
			else {
				// Printing the IPv6 address
				printf("\"%s\", ", IP);
			}
			c = 1;

			// Optional: To beautify the output on the console
			if (counter % 3 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}
int main() {
	SIZE_T ShellcodeSize = sizeof(pshellcode);
	printf("le shellcode du payload est %d\n", ShellcodeSize); // Utilisation de %llu pour SIZE_T
	printf("let's start using this method\n");
	if (GenerateIpv6Output(pshellcode, ShellcodeSize)) { // Passer pshellcode au lieu de pshellcode1

		printf("tu va bien \n");
		return 1;

	}
	printf("error ");
	return 0;
}


