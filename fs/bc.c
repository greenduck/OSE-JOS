
#include "fs.h"

// Return the virtual address of this disk block.
void*
diskaddr(uint32_t blockno)
{
	if (blockno == 0 || (super && blockno >= super->s_nblocks))
		panic("bad block number %08x in diskaddr", blockno);
	return (char*) (DISKMAP + blockno * BLKSIZE);
}

static uint32_t
diskblock(void *addr)
{
	panic_if(((addr < (void *)DISKMAP) || (addr >= (void *)(DISKMAP + DISKSIZE))), "accessing disk address out of range: %08x", addr);
	return ((uint32_t)addr - DISKMAP) / BLKSIZE;
}

/** 
 * @return 'true' if 'va' is mapped in this environment
 */ 
bool
va_is_mapped(void *va)
{
	return (uvpd[PDX(va)] & PTE_P) && (uvpt[PGNUM(va)] & PTE_P);
}

/** 
 * @return 'true' if 'va' has been write-accessed
 */ 
bool
va_is_dirty(void *va)
{
	return (uvpt[PGNUM(va)] & PTE_D) != 0;
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
	// flush cached blocks to disk, as block cache fills up
}


void
bc_init(void)
{
	struct Super super;
	set_pgfault_handler(bc_pgfault);

	// cache the super block by reading it once
	memmove(&super, diskaddr(1), sizeof super);
}



/**
 * Unmap memory page caching a disk block, while flushing block 
 * contents to the disk (only in case it is 'dirty')
 */
void
flush_block(void *addr)
{
	void *addr_fixed;
	uint32_t blockno;
	uint32_t sector;
	int perm;
	int r;

	panic_if(((addr < (void *)DISKMAP) || (addr >= (void *)(DISKMAP + DISKSIZE))), "environment %08x attempts to flush non-disk memory address: %08x", thisenv->env_id, addr);

	if (!va_is_mapped(addr))
		return;

	addr_fixed = ROUNDDOWN(addr, BLKSIZE);
	blockno = diskblock(addr_fixed);

	if (va_is_dirty(addr)) {
		sector = blockno * BLKSECTS;

		r = ide_write(sector, addr_fixed, BLKSECTS);
		panic_if(r, "could not flush block %u to disk: %e", blockno, r);

		// (!)
		if (blockno <= 2) {
			perm = uvpt[PGNUM(addr_fixed)] & PTE_SYSCALL;
			r = sys_page_map(0, addr_fixed, 0, addr_fixed, perm);
			panic_if(r, "could not re-map page %08x: %e", addr_fixed, r);
		}
	}

	// (!!)
	/*
	 * (!) and (!!) are intended to prevent undoing fs_init()
	 */
	if (blockno > 2) {
		r = sys_page_unmap(0, addr_fixed);
		panic_if(r, "could not unmap page %08x: %e", addr, r);
	}
}

