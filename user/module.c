#include <inc/lib.h>
#include <inc/string.h>
#include <inc/elf.h>
#include <inc/memlayout.h>

#define KERNEL_SYMTAB_PREFIX	"kernel"
#define MAX_NR_SEC		16

#define DEBUG

#ifdef DEBUG
#define dbg_printf		cprintf
#else
#define dbg_printf(...)
#endif


struct ModInfo {
	int		symtab_index;
	int		strtab_index;
	int		rel_text_index;
	int		text_index;
	uint32_t	tot_size;
	struct Secthdr	sec[MAX_NR_SEC];

	/* entry and exit points */
	int (*init_module)(void);
	void (*cleanup_module)(void);
};


static void print_usage(void);
static int mod_insert(const char *mod_filename);
static int mod_load_file(void *addr, int fd, struct ModInfo *info);
static int mod_relocate_text_section(void *text, int fd, struct ModInfo *info);
static int mod_load_symbols(int fd, struct ModInfo *info);

static void dbg_dump_text_section(struct ModInfo *info);

int kernel_symtab_init(void);
void kernel_symtab_cleanup(void);
Elf32_Sym *kernel_symtab_get(const char *name);
void kernel_symtab_unittest(void);

uint32_t virt_addr_translate_to_kernel(uint32_t va);

static struct ModInfo mod_info = {0};

void
umain(int argc, char **argv)
{
	/* parse command line */
	int i;
	char *name = NULL;

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
	mod_insert(name);
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

static int
mod_insert(const char *mod_filename)
{
	int mod_fd;
	int err;
	void *text;

	err = kernel_symtab_init();
	if (err < 0)
		goto out;
	kernel_symtab_unittest();

	mod_fd = open(mod_filename, O_RDONLY);
	if (mod_fd < 0) {
		cprintf("could not open file '%s': %e \n", mod_filename, mod_fd);
		err = mod_fd;
		goto out_cleanup_1;
	}

	err = sys_page_alloc(0, UTEMP, (PTE_P | PTE_U | PTE_W));
	if (err < 0) {
		cprintf("could not allocate kernel page: %e \n", err);
		goto out_cleanup_2;
	}

	err = mod_load_file(UTEMP, mod_fd, &mod_info);
	if (err != 0)
		goto out_cleanup_2;

	text = (void *)mod_info.sec[ mod_info.text_index ].sh_addr;
	err = mod_relocate_text_section(text, mod_fd, &mod_info);
	if (err != 0)
		goto out_cleanup_2;

	dbg_dump_text_section(&mod_info);
	err = mod_load_symbols(mod_fd, &mod_info);
	if (err != 0)
		goto out_cleanup_2;


out_cleanup_2:
	close(mod_fd);

out_cleanup_1:
	kernel_symtab_cleanup();

out:
	return err;
}

#ifdef DEBUG
static void
dbg_print_string_table(const char *title, const char *buff, unsigned len)
{
	int i;

	cprintf("%s ", title);
	for (i = 0; i < (31 - strlen(title)); ++i)
		cprintf("-");
	cprintf(" \n");

	for (i = 0; i < len; ++i) {
		if (buff[i]) {
			cprintf("%c", buff[i]);
		}
		else {
			cprintf("\n");
		}
	}

	cprintf("-------------------------------- \n");
}
#else
static void
dbg_print_string_table(const char *title, const char *buff, unsigned len)
{ }
#endif

#ifdef DEBUG
static void
dbg_print_symbol_names(int fd, uint32_t sym_sh_offset, uint32_t sym_sh_size)
{
	char buff[128];
	seek(fd, sym_sh_offset);
	readn(fd, buff, sym_sh_size);
	dbg_print_string_table("module symbol names", buff, sym_sh_size);
}
#else
static void
dbg_print_symbol_names(int fd, uint32_t sym_sh_offset, uint32_t sym_sh_size)
{ }
#endif

#ifdef DEBUG
static void
dbg_print_relocation_table(int fd, uint32_t rel_sh_offset, uint32_t rel_sh_size)
{
	struct elf32_rel rel;
	int count = rel_sh_size / sizeof(struct elf32_rel);
	int i;

	cprintf("relocation table --------------- \n");
	for (i = 0; i < count; ++i) {
		seek(fd, (rel_sh_offset + (i * sizeof(struct elf32_rel))));
		readn(fd, &rel, sizeof(struct elf32_rel));
		cprintf("%08x  %06x|%02x \n", rel.r_offset, ELF32_R_SYM(rel.r_info), ELF32_R_TYPE(rel.r_info));
	}
	cprintf("-------------------------------- \n");
}
#else
static void
dbg_print_relocation_table(int fd, uint32_t rel_sh_offset, uint32_t rel_sh_size)
{ }
#endif

#ifdef DEBUG
static void
dbg_dump_text_section(struct ModInfo *info)
{
	int i;
	struct Secthdr *text_sec = &info->sec[ info->text_index ];

	cprintf("text section dump -------------- \n");
	for (i = 0; i < text_sec->sh_size; ++i) {
			if (i % 16 == 0)
				cprintf("%s[%2x]", (i > 0 ? "\n" : ""), i);
			cprintf(" %02x", ((unsigned char *)text_sec->sh_addr)[i]);
	}
	cprintf("\n-------------------------------- \n");
}

#else

static void
dbg_dump_text_section(struct ModInfo *info)
{ }
#endif

static int
mod_load_file(void *addr, int fd, struct ModInfo *info)
{
	struct Elf elf;
	struct Secthdr sec;
	char string_buff[512];
	int i;
	char *sec_name;
	uint32_t fixed_size;

	readn(fd, &elf, sizeof(struct Elf));

	if (elf.e_magic != ELF_MAGIC) {
		cprintf("bad or missing ELF magic: %08x (expected %08x) \n", elf.e_magic, ELF_MAGIC);
		return -E_NOT_EXEC;
	}
	if (elf.e_shnum > MAX_NR_SEC) {
		cprintf("ELF object contains too many sections (%d) \n", elf.e_shnum);
		return -E_NO_MEM;
	}

	/* read section name 'strings' */
	seek(fd, (elf.e_shoff + (elf.e_shstrndx * sizeof(struct Secthdr))));
	readn(fd, &sec, sizeof(struct Secthdr));

	if (sec.sh_size > sizeof(string_buff)) {
		cprintf("ELF strings section is too big (%d bytes) \n", sec.sh_size);
		return -E_NO_MEM;
	}
	seek(fd, sec.sh_offset);
	readn(fd, string_buff, sec.sh_size);
	dbg_print_string_table("section names", string_buff, sec.sh_size);

	/* traverse all ELF sections ... */
	for (i = 0; i < elf.e_shnum; ++i) {
		if (i == elf.e_shstrndx)
			continue;

		seek(fd, (elf.e_shoff + (i * sizeof(struct Secthdr))));
		readn(fd, &sec, sizeof(struct Secthdr));
		sec_name = (string_buff + sec.sh_name);
		info->sec[i] = sec;
		dbg_printf("[%2d] %s ", i, sec_name);

		switch (sec.sh_type)
		{
		case ELF_SHT_SYMTAB:
			dbg_printf("[SYM] \n");
			if (!strcmp(".symtab", sec_name)) {
				info->symtab_index = i;
			}
			break;

		case ELF_SHT_STRTAB:
			dbg_printf("[STR] \n");
			if (!strcmp(".strtab", sec_name)) {
				info->strtab_index = i;
				// dbg_print_symbol_names(fd, sec.sh_offset, sec.sh_size);
			}
			break;

		case ELF_SHT_REL:
			dbg_printf("[REL] \n");
			if (!strcmp(".rel.text", sec_name)) {
				info->rel_text_index = i;
				// dbg_print_relocation_table(fd, sec.sh_offset, sec.sh_size);
			}
			break;

		case ELF_SHT_NOBITS:
			if ((sec.sh_flags & SHF_ALLOC) && (sec.sh_size > 0)) {
				memset(addr, 0, sec.sh_size);

				info->sec[i].sh_addr = (uint32_t)addr;
				fixed_size = ROUNDUP(sec.sh_size, sizeof(uint32_t));
				info->tot_size += fixed_size;
				addr += fixed_size;
			}
			break;

		case ELF_SHT_PROGBITS:
		default:
			if ((sec.sh_flags & SHF_ALLOC) && (sec.sh_size > 0)) {
				if (!strcmp(".text", sec_name))
					info->text_index = i;

				seek(fd, sec.sh_offset);
				readn(fd, addr, sec.sh_size);

				info->sec[i].sh_addr = (uint32_t)addr;
				fixed_size = ROUNDUP(sec.sh_size, sizeof(uint32_t));
				info->tot_size += fixed_size;
				addr += fixed_size;
			}
			break;
		}
	}

	return 0;
}

static int
mod_relocate_text_section(void *text, int fd, struct ModInfo *info)
{
	struct Secthdr *sym_sec = &info->sec[ info->symtab_index ];
	struct Secthdr *str_sec = &info->sec[ info->strtab_index ];
	struct Secthdr *rel_sec = &info->sec[ info->rel_text_index ];

	uint32_t r_offset;
	uint32_t r_sym;
	uint8_t r_type;
	uint8_t st_bind;

	int i;
	int line = -1;

	char symbol_names[512];
	char *name;
	uint32_t value;
	int sec_index;
	Elf32_Sym rel_sym;
	uint32_t kaddr;

	struct elf32_rel rel;
	int count = rel_sec->sh_size / sizeof(struct elf32_rel);



	if (str_sec->sh_size > sizeof(symbol_names)) {
		cprintf("ELF .strtab section is too big (%d bytes) \n", str_sec->sh_size);
		return -E_NO_MEM;
	}
	seek(fd, str_sec->sh_offset);
	readn(fd, symbol_names, str_sec->sh_size);
	dbg_print_string_table("local symbol names", symbol_names, str_sec->sh_size);



	/* for each relocation ... */
	for (i = 0; i < count; ++i) {
		seek(fd, (rel_sec->sh_offset + (i * sizeof(struct elf32_rel))));
		readn(fd, &rel, sizeof(struct elf32_rel));

		r_offset = rel.r_offset;
		r_sym = ELF32_R_SYM(rel.r_info);
		r_type = ELF32_R_TYPE(rel.r_info);
		dbg_printf("%2d: %08x %06x|%02x ", i, r_offset, r_sym, r_type);

		/* read symbol being relocated */
		seek(fd, (sym_sec->sh_offset + (r_sym * sizeof(Elf32_Sym))));
		readn(fd, &rel_sym, sizeof(Elf32_Sym));

		if (rel_sym.st_name != 0) {
			/* named symbol: function or global variable */

			name = (symbol_names + rel_sym.st_name);
			st_bind = ELF_ST_BIND(rel_sym.st_info);
			dbg_printf("[%s: bind = %d  ndx = %d] \n", name, st_bind, rel_sym.st_shndx);
			if (rel_sym.st_shndx > 0) {
				/* symbol defined in 'this module's' sections */
				value = rel_sym.st_value;
			}
			else {
				/* symbol is (supposedly) defined in the kernel symbol table */
				value = kernel_symtab_get(name)->st_value;
			}

			switch (r_type)
			{
			case R_386_32:		/* Direct 32 bit  */
				*(uint32_t *)(text + r_offset) = value;
				break;

			case R_386_PC32:	/* PC relative 32 bit */
				kaddr = virt_addr_translate_to_kernel((uint32_t)text);
				cprintf("user to kernel address translation: %08x -> %08x \n", (uint32_t)text, kaddr);
				*(uint32_t *)(text + r_offset) = value - (kaddr + r_offset + 4);
				break;

			default:
				line = __LINE__;
				goto out_not_supported_reloc_type;
			}
		}
		else {
			/* unnamed (local) symbol in  .rodata, .bss, .data  sections */

			dbg_printf("[unnamed] \n");
			if (r_type != R_386_32) {
				line = __LINE__;
				goto out_not_supported_reloc_type;
			}

			sec_index = rel_sym.st_shndx;
			if ((sec_index < 0) || (sec_index >= MAX_NR_SEC))
				goto out_index_out_of_range;

			kaddr = virt_addr_translate_to_kernel( info->sec[sec_index].sh_addr );
			cprintf("user to kernel address translation: %08x -> %08x \n", info->sec[sec_index].sh_addr, kaddr);
			/* read-modify-write */
			*(uint32_t *)(text + r_offset) = *(uint32_t *)(text + r_offset) + kaddr;
		}
	}

	return 0;

out_not_supported_reloc_type:
	cprintf("This implementation is missing support for relocation type %d (line %d) \n", r_type, line);
	return -E_NOT_SUPP;

out_not_supported_sym_binding:
	cprintf("This implementation is missing suuport for symbol binding type %d \n", ELF_ST_BIND(rel_sym.st_info));
	return -E_NOT_SUPP;

out_index_out_of_range:
	cprintf("Section index out of range: %d \n", sec_index);
	return -E_INVAL;
}

/** 
 * Currently we identify module entry / exit points as totally
 * essential.
 * As a future enhancement one could add all these symbols to
 * the kernel symbol table allowing other modules to
 * (dynamically) link against this one.
 */ 
static int
mod_load_symbols(int fd, struct ModInfo *info)
{
	struct Secthdr *sym_sec = &info->sec[ info->symtab_index ];
	struct Secthdr *str_sec = &info->sec[ info->strtab_index ];
	Elf32_Sym sym;
	char symbol_names[512];
	int count;
	int i;
	int err = -2;

	uint32_t text;
	uint32_t ktext;

	if (str_sec->sh_size > sizeof(symbol_names)) {
		cprintf("ELF .strtab section is too big (%d bytes) \n", str_sec->sh_size);
		return -E_NO_MEM;
	}

	/* one last relocation ... */
	text = info->sec[ info->text_index ].sh_addr;
	ktext = virt_addr_translate_to_kernel(text);

	seek(fd, str_sec->sh_offset);
	readn(fd, symbol_names, str_sec->sh_size);

	count = sym_sec->sh_size / sizeof(Elf32_Sym);
	for (i = 0; i < count; ++i) {
		seek(fd, (sym_sec->sh_offset + (i * sizeof(Elf32_Sym))));
		readn(fd, &sym, sizeof(Elf32_Sym));

		if (!strcmp("init_module", (symbol_names + sym.st_name))) {
			info->init_module = (void *)(sym.st_value + ktext);
			++err;
		}
		else if (!strcmp("cleanup_module", (symbol_names + sym.st_name))) {
			info->cleanup_module = (void *)(sym.st_value + ktext);
			++err;
        	}
	}

	if (err != 0)
		cprintf("%d essential module symbols could not be identified \n", -err);
	return err;
}

// ------------------------
static int fd_symtab;
static int fd_strtab;

int
kernel_symtab_init(void)
{
	char *filename;
	int err;

	filename = KERNEL_SYMTAB_PREFIX".symtab";
	fd_symtab = open(filename, O_RDONLY);
	if (fd_symtab < 0) {
		cprintf("could not open file '%s': %e \n", filename, fd_symtab);
		err = fd_symtab;
		goto out;
	}

	filename = KERNEL_SYMTAB_PREFIX".strtab";
	fd_strtab = open(filename, O_RDONLY);
	if (fd_strtab < 0) {
		cprintf("could not open file '%s': %e \n", filename, fd_strtab);
		err = fd_strtab;
		goto out_cleanup_1;
	}

	return 0;

out_cleanup_1:
	close(fd_symtab);

out:
	return err;
}

void
kernel_symtab_cleanup(void)
{
	close(fd_symtab);
	close(fd_strtab);
}

static int
kernel_symtab_get_index_by_name(const char *name)
{
	char string_buff[512];
	off_t offset;
	off_t delta;
	int terminate;
	int i;
	int n;

	offset = 0;
	terminate = 0;
	while (!terminate) {
		seek(fd_strtab, offset);
		n = readn(fd_strtab, string_buff, sizeof(string_buff));
		if (n < sizeof(string_buff))
			terminate = 1;

		delta = 0;
		for (i = 0; i < (n - strlen(name)); ++i, ++delta) {
			if (string_buff[i] == name[0]) {
				offset += delta;
				delta = 0;
				if (!strcmp(&string_buff[i], name)) {
					/* hallelujah */
					return (int)offset;
				}
			}
			else if (string_buff[i] == 0) {
				offset += delta;
				delta = 0;
			}
		}
	}

	cprintf("kernel symbol could not be found: %s \n", name);
	return -E_NOT_FOUND;
}

Elf32_Sym *
kernel_symtab_get(const char *name)
{
	static Elf32_Sym ksym;
	int sym_index;
	off_t offset;
	int n;

	sym_index = kernel_symtab_get_index_by_name(name);
	if (sym_index < 0)
		return NULL;


	for (offset = 0; ; offset += sizeof(Elf32_Sym)) {
		seek(fd_symtab, offset);
		n = readn(fd_symtab, &ksym, sizeof(Elf32_Sym));
		if (n < sizeof(Elf32_Sym))
			break;

		/* ATTENTION !
		 * we always return pointer to the same object, 
		 * meaning there is no reason to deal with more than 1 kernel symbol 
		 * at the same time. 
		 */
		if (ksym.st_name == sym_index)
			return &ksym;
	}

	cprintf("BUG: kernel symbol could not be found after successful name identification: %d \n", name);
	return NULL;
}

#ifdef DEBUG
void
kernel_symtab_unittest(void)
{
	char *name[] = {
		"try_to_run",
		"cprintf",
		"strcpy",
		"kbd_intr",
		"i386_init",
		"print_trapframe",
		"ismp",
		"andrey_rules"
	};

	int i;
	Elf32_Sym *sym;
	uint32_t value;
	int expected;

	for (i = 0; i < 8; ++i) {
		sym = kernel_symtab_get(name[i]);
		if (i < 7) {
			expected = (sym != NULL);
			value = sym->st_value;
		}
		else {
			expected = (sym == NULL);
			value = 0xffffffff;
		}

		cprintf("%s: %s  [%s : %08x] \n", __FUNCTION__, (expected ? "OK" : "FAILURE"), name[i], value);
	}
}

#else

void
kernel_symtab_unittest(void)
{ }
#endif

// ------------------------
/* imported from pmap.h */
#define KADDR(pa)	(pa + KERNBASE)

/**
 * The magic formula that translates user-space address to
 * kernel address.
 */
uint32_t
virt_addr_translate_to_kernel(uint32_t va)
{
	pte_t pgtab_entry = uvpt[PGNUM(va)];
	return KADDR( PTE_ADDR( pgtab_entry )) + PGOFF(va);
}
// ------------------------

