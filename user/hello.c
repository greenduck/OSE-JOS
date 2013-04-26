// hello, world
#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	volatile int x = 3;
	volatile int y = 5;
	volatile int z = 0;

	// trivial code that can easily be identified in a disassembly
	z = x + y;
	cprintf("hello, world (%d) \n", z);
	cprintf("i am environment %08x\n", thisenv->env_id);
}
