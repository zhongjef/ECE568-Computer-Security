#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int
foo ( char *arg )
{
	char	buf[252];
	int	p, j, len;

	p = 272;
	len = (strlen(arg) > p) ? p : strlen(arg);
  
	for (j = 0; j <= len; j++)
		buf[j] = arg[j];

	return (0);
}

int
lab_main ( int argc, char *argv[] )
{
	int	t = 2;

	printf ("Target2 running.\n");

	if (argc != t)
	{
		fprintf ( stderr, "target2: argc != 2\n" );
		exit ( EXIT_FAILURE );
	}

	foo ( argv[1] );

	return (0);
}
