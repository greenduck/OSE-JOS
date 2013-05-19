// Called from entry.S to get us going.
// entry.S already took care of defining envs, pages, uvpd, and uvpt.

#include <inc/lib.h>

extern void umain(int argc, char **argv);

const volatile struct Env **ref_thisenv;
const char *binaryname = "<unknown>";

void
libmain(int argc, char **argv)
{
	envid_t envid;
	const volatile struct Env *thisenv_on_stack;

	// set thisenv to point at our Env structure in envs[].
	envid = sys_getenvid();
	thisenv_on_stack = &envs[ENVX(envid)];
	ref_thisenv = &thisenv_on_stack;

	// save the name of the program so that panic() can use it
	if (argc > 0)
		binaryname = argv[0];

	// call user main routine
	umain(argc, argv);

	// exit gracefully
	exit();
}

