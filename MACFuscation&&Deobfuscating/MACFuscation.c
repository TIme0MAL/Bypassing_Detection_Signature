#include <stdio.h>
#include <Windows.h>
#include <stdlib.h> // Pour malloc
#define _CRT_SECURE_NO_WARNINGS

unsigned char pShellcode[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8,
0xC0, 0x00, 0x00, 0x00, 0x41, 0x51 };


char* GenerateMAC(int a, int b, int c, int d, int e, int f) {
	char* Output = (char*)malloc(64 * sizeof(char));
	if (Output == NULL) {
		printf("pas d'allocation dynamique\n");
		return NULL;
	}


	// Creating the MAC address and saving it to the 'Output' variable 
	sprintf_s(Output, 64, "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X", a, b, c, d, e, f);

	// Optional: Print the 'Output' variable to the console
	// printf("[i] Output: %s\n", Output);

	return Output;
}

// Generate the MAC output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {


	// If the shellcode buffer is null or the size is not a multiple of 6, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 6 != 0) {
		printf("hamza");
		printf("youssra");
		return FALSE;




	}
	printf("char* MacArray [%d] = {\n\t", (int)(ShellcodeSize / 6));

	// We will read one shellcode byte at a time, when the total is 6, begin generating the MAC address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 6.
	int c = 6, counter = 0;
	char* Mac = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {

		// Track the number of bytes read and when they reach 6 we enter this if statement to begin generating the MAC address
		if (c == 6) {
			counter++;

			// Generating the MAC address from 6 bytes which begin at i until [i + 5] 
			Mac = GenerateMAC(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3], pShellcode[i + 4], pShellcode[i + 5]);

			if (i == ShellcodeSize - 6) {

				// Printing the last MAC address
				printf("\"%s\"", Mac);
				break;
			}
			else {
				// Printing the MAC address
				printf("\"%s\", ", Mac);
			}
			c = 1;
			free(Mac);

			// Optional: To beautify the output on the console
			if (counter % 6 == 0) {
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
	SIZE_T ShellcodeSize = sizeof(pShellcode);

	printf("le shellcode du payload est de taille %d\n", ShellcodeSize); // Utilisation de %llu pour SIZE_T
	printf("let's start using this method\n");

	if (GenerateMacOutput(pShellcode, ShellcodeSize)) {
		printf("tu va bien \n");
		printf("\n");
		printf("ahmed");

		// Free the allocated memory after use
		return 0;
	}

	printf("error ");
	return 1;
}