#include "inc/stdio.h"

int random_num(void)
{
	volatile int num = num;
	return num;
}

int init_module(void)
{
	cprintf("Kernel module: Hello world (%d) \n", random_num());
	return 0;
}

void cleanup_module(void)
{
	cprintf("Kernel module: Adios world \n");
}

