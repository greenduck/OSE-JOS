#include "inc/stdio.h"

int init_module(void)
{
	cprintf("Kernel module: Hello world \n");
	return 0;
}

void cleanup_module(void)
{
	cprintf("Kernel module: Adios world \n");
}

