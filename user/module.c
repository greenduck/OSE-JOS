#include <inc/lib.h>
#include <inc/string.h>

static void print_usage(void);

void
umain(int argc, char **argv)
{
	/* parse command line */
	int i;
	char *name;

	for (i = 1; i < (argc - 1); ++i) {
		if (!strncmp("insert", argv[i], 6)) {
			name = argv[i + 1];
			goto mod_insert;
		}

		if (!strncmp("remove", argv[i], 6)) {
			name = argv[i + 1];
			goto mod_remove;
		}

		if (!strncmp("list", argv[i], 4)) {
			goto mod_list;
		}
	}

	print_usage();

mod_insert:
	cprintf("mod_insert: not yet implemented \n");
	return;

mod_remove:
	cprintf("mod_remove: not yet implemented \n");
	return;

mod_list:
	cprintf("mod_list: not yet implemented \n");
	return;
}

static void
print_usage(void)
{
	cprintf("Usage: \n");
	cprintf("module insert <module-file-name> \n");
	cprintf("module remove <module-name> \n");
	cprintf("module list \n");
	exit();
}

