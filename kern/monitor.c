// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help",		"Display this list of commands",		mon_help },
	{ "kerninfo",		"Display information about the kernel",		mon_kerninfo },
	{ "backtrace",		"Display stack backtrace",			mon_backtrace },
	{ "showmappings",	"Display virtual memory pages mapping",		mon_showmappings },
	{ "mapping_perms",	"Edit memory mapping permissions",		mon_mapping_perms },
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t ebp;
	uint32_t ret_addr;
	int i;
	struct Eipdebuginfo info;

	ebp = read_ebp();
	while (ebp != 0) {
		ret_addr = *((uint32_t *)(ebp + 4));
		cprintf("ebp %08x  eip %08x  args", ebp, ret_addr);
		for (i = 0; i < 5; ++i)
			cprintf(" %08x", *((uint32_t *)(ebp + 4 * (i + 2))));
		cprintf("\n");

		debuginfo_eip(ret_addr, &info);
		cprintf("\t%s:%d: %.*s+%x \n",
			info.eip_file,
			info.eip_line,
			info.eip_fn_namelen,
			info.eip_fn_name,
			(unsigned int)(ret_addr - info.eip_fn_addr));

		ebp = *((uint32_t *)ebp);
	}
	return 0;
}



#define TABENTRY_ADDR(addr)	(PTE_ADDR(addr) >> 12)
#define TABENTRY_FLAGS(addr)	((addr) & 0xfff)

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf)
{
	uintptr_t start, stop;
	pde_t *pgdir_entry;
	physaddr_t pgtab;
	pte_t *pgtab_entry;

	if (argc > 1) {
		start = strtol(argv[1], NULL, 0);
		if (argc > 2)
			stop = strtol(argv[2], NULL, 0);
		else
			stop = start;
	}
	else {
		cprintf("Erroneous arguments: \n");
		cprintf("%s start-addr [stop-addr] \n", argv[0]);
		return 0;
	}

	cprintf("index____  virt_addr_  page_dir___  page_tab___ \n");
	for (start = ROUNDDOWN(start, PGSIZE), stop = ROUNDUP(stop, PGSIZE); start <= stop; start += PGSIZE) {
		cprintf("%04d:%04d  0x%08x  ", PDX(start), PTX(start), start);

		pgdir_entry = &kern_pgdir[PDX(start)];
		if ( !(*pgdir_entry & PTE_P) ) {
			cprintf("UNMAPPED");
		}
		else {
			cprintf("[%05x|%03x]  ", TABENTRY_ADDR(*pgdir_entry), TABENTRY_FLAGS(*pgdir_entry));

			pgtab = PTE_ADDR(*pgdir_entry);
			pgtab_entry = &((pte_t *)KADDR(pgtab))[PTX(start)];
			if ( !(*pgtab_entry & PTE_P) ) {
				cprintf("UNMAPPED");
			}
			else {
				cprintf("[%05x|%03x]  ", TABENTRY_ADDR(*pgtab_entry), TABENTRY_FLAGS(*pgtab_entry));
			}
		}

		cprintf("\n");
	}

	return 0;
}

#define ALLOWED_FLAGS	(PTE_AVAIL | PTE_PCD | PTE_PWT | PTE_U | PTE_W)

int
mon_mapping_perms(int argc, char **argv, struct Trapframe *tf)
{
	int pgdir_index, pgtab_index;
	char *insight;
	int set_permissions = 0;
	uint32_t new_permissions = 0;
	pde_t *pgdir_entry;
	physaddr_t pgtab;
	pte_t *pgtab_entry;
	uint32_t **entry;

	if (argc > 1) {
		pgdir_index = strtol(argv[1], &insight, 0);
		if (*insight == ':')
			pgtab_index = strtol(&insight[1], NULL, 0);
		else
			pgtab_index = -1;

		if (argc > 2) {
			new_permissions = strtol(argv[2], NULL, 0);
			set_permissions = 1;
		}
	}
	else {
		cprintf("Erroneous arguments: \n");
		cprintf("%s page-dir-index[:page-tab-index]  -  display permissions for page directory entry [or page table entry] \n", argv[0]);
		cprintf("%s page-dir-index[:page-tab-index] new-perms  -  set new permissions for pagedir or pagetab entry \n", argv[0]);
		return 0;
	}

	pgdir_entry = &kern_pgdir[pgdir_index];
	entry = &pgdir_entry;
	if ( !(*pgdir_entry & PTE_P) ) {
		cprintf("Page directory entry %d is not present \n", pgdir_index);
		return 0;
	}
	if (pgtab_index >= 0) {
		pgtab = PTE_ADDR(*pgdir_entry);
		pgtab_entry = &((pte_t *)KADDR(pgtab))[pgtab_index];
		if ( !(*pgtab_entry & PTE_P) ) {
			cprintf("Page table entry %d is not present \n", pgtab_index);
			return 0;
		}
		entry = &pgtab_entry;
	}

	if ( !set_permissions ) {
		cprintf("%3x \n", TABENTRY_FLAGS(**entry));
	}
	else {
		**entry = (**entry & ~ALLOWED_FLAGS) | (new_permissions & ALLOWED_FLAGS);

		if (pgtab_index >= 0) {
			// any address will invalidate the whole page
			tlb_invalidate(kern_pgdir, PGADDR(pgdir_index, pgtab_index, 0));
		}
		else {
			// invalidate each page belonging to 'this' directory
			pgtab = PTE_ADDR(*pgdir_entry);
			for (pgtab_index = 0; pgtab_index < (1 << (PDXSHIFT - PTXSHIFT)); ++pgtab_index) {
				pgtab_entry = &((pte_t *)KADDR(pgtab))[pgtab_index];
				if ( *pgtab_entry & PTE_P ) {
					tlb_invalidate(kern_pgdir, PGADDR(pgdir_index, pgtab_index, 0));
				}
			}
		}
	}

	return 0;
}



/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");


	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
