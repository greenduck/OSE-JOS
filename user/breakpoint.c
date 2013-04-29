// program to cause a breakpoint trap

#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	asm volatile("int $3");

	{
		/* a little something to debug */

		volatile int a;
		volatile int b;
		volatile int c;

		a = 3;
		b = 5;
		c = a + b;
		c <<= 1;
		b = 0;
		c = a / b;
	}
}

