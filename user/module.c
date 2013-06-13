#include <inc/lib.h>
#include <inc/string.h>
#include <inc/elf.h>

#define SYMTAB_FILENAME		"kernel.sym"
#define MAX_NR_SEC		16

#define DEBUG

#ifdef DEBUG
#define dbg_printf		cprintf
#else
#define dbg_printf(...)
#endif


struct ModInfo {
	int symtab_index;
	int strtab_index;
	int rel_text_index;
	struct Secthdr sec[MAX_NR_SEC];
};


static void print_usage(void);
static int mod_insert(const char *mod_filename, const char *symtab_filename);
static int mod_load_file(void *addr, int fd, struct ModInfo *info);
static int mod_relocate_text_section(void *text, int fd, struct ModInfo *info);

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
	mod_insert(name, SYMTAB_FILENAME);
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
mod_insert(const char *mod_filename, const char *symtab_filename)
{
	int mod_fd;
	int symtab_fd;
	int err = 0;

	symtab_fd = open(symtab_filename, O_RDONLY);
	if (symtab_fd < 0) {
		cprintf("could not open file '%s': %e \n", symtab_filename, symtab_fd);
		err = symtab_fd;
		goto out;
	}

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


out_cleanup_2:
	close(mod_fd);

out_cleanup_1:
	close(symtab_fd);

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

static int
mod_load_file(void *addr, int fd, struct ModInfo *info)
{
	struct Elf elf;
	struct Secthdr sec;
	char string_buff[512];
	int i;
	char *sec_name;

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
				dbg_print_symbol_names(fd, sec.sh_offset, sec.sh_size);
			}
			break;

		case ELF_SHT_REL:
			dbg_printf("[REL] \n");
			if (!strcmp(".rel.text", sec_name)) {
				info->rel_text_index = i;
				dbg_print_relocation_table(fd, sec.sh_offset, sec.sh_size);
			}
			break;

		default:
			if ( !((sec.sh_flags & SHF_ALLOC) && (sec.sh_size > 0) && (sec.sh_addr == 0)) ) {
				dbg_printf("[---] \n");
				break;
			}

			if (sec.sh_type == ELF_SHT_NOBITS) {
				memset(addr, 0, sec.sh_size);
			}
			else {
				seek(fd, sec.sh_offset);
				readn(fd, addr, sec.sh_size);
			}
			addr += sec.sh_size;
			dbg_printf("[+++] \n");
			break;
		}
	}

	return 0;
}
#if 0
static int
mod_relocate_text_section(void *text, int fd, struct ModInfo *info)
{
	struct Secthdr *sym_sec = &info->sec[ info->symtab_index ];
	struct Secthdr *str_sec = &info->sec[ info->strtab_index ];
	struct Secthdr *rel_sec = &info->sec[ info->rel_text_index ];

	uint32_t r_offset;
	uint32_t r_sym;
	uint8_t r_type;

	int i;
	int line = -1;
	uint32_t value;
	char symbol_names[512];

	struct elf32_rel rel;
	int count = rel_sec->sh_size / sizeof(struct elf32_rel);



	if (str_sec->sh_size > sizeof(symbol_names)) {
		cprintf("ELF .strtab section is too big (%d bytes) \n", str_sec->sh_size);
		return -E_NO_MEM;
	}
	seek(fd, str_sec->sh_offset);
	readn(fd, symbol_names, str_sec->sh_size);



	/* for each relocation ... */
	for (i = 0; i < count; ++i) {
		seek(fd, (rel_sec->sh_offset + (i * sizeof(struct elf32_rel))));
		readn(fd, &rel, sizeof(struct elf32_rel));

		r_offset = rel.r_offset;
		r_sym = ELF32_R_SYM(rel.r_info);
		r_type = ELF32_R_TYPE(rel.r_info);

		if (FIXME_symbol_name[0] != 0) {
			/* .text */

			value = FIXME_symbol_value(FIXME_symbol_name);

			switch (r_type)
			{
			case R_386_32:		/* Direct 32 bit  */
				*(uint32_t *)(text + r_offset) = value;
				break;

			case R_386_PC32:	/* PC relative 32 bit */
				*(uint32_t *)(text + r_offset) = value - (FIXME_to_kernel_address( text ) + r_offset + 4);
				break;

			default:
				line = __LINE__;
				goto out_not_supported;
			}
		}
		else {
			/* .rodata, .bss, .data */

			if (r_type != R_386_32) {
				line = __LINE__;
				goto out_not_supported;
			}

			ndx = FIXME_symbol_ndx;
			addr = FIXME_to_kernel_address( info->sections[ndx].addr );
			/* read-modify-write */
			*(uint32_t *)(text + r_offset) = *(uint32_t *)(text + r_offset) + addr;
		}
	}

	return 0;

out_not_supported:
	cprintf("This implementation is missing support for relocation type %d \n", r_type);
	return -E_NOT_SUPP;
}
#endif
