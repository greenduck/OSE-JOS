// buggy program - causes an illegal software interrupt
/*
 * In practice this program generates 'general protection exception' - INT 13. 
 * Q: Why not INT 14, as it is what is written in the code ? 
 * A: Because no user process is PERMITTED to perform INT 14. 
 *      The lack of permission causes the exception.
 *      This theory can easily be tested by setting INT 14's DPL to 3.
 */

#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	asm volatile("int $14");	// page fault
}

