
#include "fs.h"

// Return the virtual address of this disk block.
void*
diskaddr(uint32_t blockno)
{
	if (blockno == 0 || (super && blockno >= super->s_nblocks))
		panic("bad block number %08x in diskaddr", blockno);
	return (char*) (DISKMAP + blockno * BLKSIZE);
}

// Fault any disk block that is read in to memory by
// loading it from disk.
static void
bc_pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t blockno = ((uint32_t)addr - DISKMAP) / BLKSIZE;
	int r;

	// Check that the fault was within the block cache region
	if (addr < (void*)DISKMAP || addr >= (void*)(DISKMAP + DISKSIZE))
		panic("page fault in FS: eip %08x, va %08x, err %04x",
		      utf->utf_eip, addr, utf->utf_err);

	// Sanity check the block number.
	if (super && blockno >= super->s_nblocks)
		panic("reading non-existent block %08x\n", blockno);

	// Allocate a page in the disk map region, read the contents
	// of the block from the disk into that page.
	// Hint: first round addr to page boundary.

	// generally, it should be rounded to common-divisor(PGSIZE, BLKSIZE) ...
	void *addr_fixed = ROUNDDOWN(addr, BLKSIZE);
	r = sys_page_alloc(0, addr_fixed, (PTE_U | PTE_W | PTE_P));
	panic_if(r, "could not allocate page: %e", r);
	uint32_t start_sector = ((uint32_t)addr_fixed - DISKMAP) / BLKSIZE * BLKSECTS;
	r = ide_read(start_sector, addr_fixed, BLKSECTS);
	panic_if(r, "could not read sector %u from disk drive: %e", r);

	// TODO:
	// flush cached blocks to disk
}


void
bc_init(void)
{
	struct Super super;
	set_pgfault_handler(bc_pgfault);

	// cache the super block by reading it once
	memmove(&super, diskaddr(1), sizeof super);
}

