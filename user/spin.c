// Test preemption by forking off a child process that just spins forever.
// Let it run for a couple time slices, then kill it.

#include <inc/lib.h>

volatile int globally_shared = 0;

void
umain(int argc, char **argv)
{
	envid_t env;
	volatile int local = 0;

	cprintf("I am the parent.  Forking the child...\n");
	if ((env = sfork()) == 0) {
		cprintf("I am the child.  Spinning...\n");
		while (1) {
			/* do nothing */
			if (globally_shared > local) {
				cprintf("[child:%x] %d <- %d \n", thisenv->env_id, local, globally_shared);
				local = globally_shared;
				--globally_shared;
			}
		}
	}

	cprintf("I am the parent.  Running the child...\n");
	sys_yield();
	sys_yield();

	local = 10;
	globally_shared = 1;

	sys_yield();
	sys_yield();

	while (globally_shared == 1);
	cprintf("[parent:%x] %d \n", thisenv->env_id, globally_shared);
	globally_shared = 2;

	sys_yield();
	sys_yield();

	while (globally_shared == 2);
	cprintf("[parent:%x] %d \n", thisenv->env_id, globally_shared);
	globally_shared = 3;

	sys_yield();
	sys_yield();

	cprintf("I am the parent.  Killing the child...\n");
	sys_env_destroy(env);
}

