#include "inc/stdio.h"

static int c;

int transmogrify(int a, int b)
{
	return (a + b) * c;
}

int init_module(void)
{
	c = 4;
	cprintf("Kernel module: Hello world (%d) \n", transmogrify(5, 3));
	return 0;
}

void cleanup_module(void)
{
	cprintf("Kernel module: Adios world \n");
}

