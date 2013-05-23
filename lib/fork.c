// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	void *fixed_addr = ROUNDDOWN(addr, PGSIZE);
	void *temp_addr = (void *)PFTEMP;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	pte_t pte = uvpt[PGNUM(addr)];
	int perm = pte & PTE_SYSCALL;
	int new_perm = (perm & ~PTE_COW) | PTE_W;
	if ( !((err & FEC_WR) && (perm & PTE_COW)) ) {
		panic("[%08x] unexpected user page fault at address: 0x%08x", thisenv->env_id, (uintptr_t)addr);
	}

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.
	//   No need to explicitly delete the old page's mapping.

	/* 
	 * after one environment copies-on-write, 
	 * the other can simply remove the COW bit 
	 */
	if (pages[PGNUM(PTE_ADDR(pte))].pp_ref == 1) {
		r = sys_page_map(0, fixed_addr, 0, fixed_addr, new_perm);
		panic_if(r, "could not re-map page");
		return;
	}

	r = sys_page_alloc(0, temp_addr, new_perm);
	panic_if(r, "could not allocate page");
	memcpy(temp_addr, fixed_addr, PGSIZE);

	r = sys_page_map(0, temp_addr, 0, fixed_addr, new_perm);
	panic_if(r, "could not map page");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.
// Q: Why do we need to mark ours copy-on-write again if it was already copy-on-write at the beginning of
//    this function?
// A: It has something to do with reference counting of allocated pages ...
//    Let us pay attention that a COW page will not turn back into W, it will rather
//    be copied to a newly allocated page by everyone of its co-owners.
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	pte_t pte = uvpt[pn];
	void *va = (void *)(pn << PGSHIFT);
	int perm = pte & PTE_SYSCALL;
	int new_perm;
	int ret;

	if ((perm & PTE_W) || (perm & PTE_COW)) {
		new_perm = (perm & ~PTE_W) | PTE_COW;
	}
	else {
		new_perm = perm;
	}

	ret = sys_page_map(0, va, envid, va, new_perm);
	if ((ret == 0) && (new_perm | PTE_COW)) {
		ret = sys_page_map(0, va, 0, va, new_perm);
	}

	return ret;
}

static int
share_page(envid_t envid, unsigned pn)
{
	pte_t pte = uvpt[pn];
	void *va = (void *)(pn << PGSHIFT);
	int perm = pte & PTE_SYSCALL;
	int ret;

	ret = sys_page_map(0, va, envid, va, perm);

	return ret;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	envid_t envid;
	unsigned pdi;
	unsigned pti;
	unsigned pn;
	int err;

	// (1)
	set_pgfault_handler(pgfault);
	// (2)
	envid = sys_exofork();
	if (envid == 0) {
		/* child process */
		/* fix 'thisenv' */
		thisenv = &envs[ENVX(sys_getenvid())];
	}
	else if (envid > 0) {
		/* parent process */
		/* complete configuration */
		// (3)
		// traverse all mapped pages
		for (pdi = 0; pdi < PDX(UTOP); ++pdi) {
			if ( !(uvpd[pdi] & PTE_P) )
				continue;

			for (pti = 0; pti < NPTENTRIES; ++pti) {
				pn = PGNUM(PGADDR(pdi, pti, 0));
				/* 
				 * skip non-existent pages 
				 * OR exception stack, which is allocated separately 
				 */
				if ( !(uvpt[pn] & PTE_P) || (pn == PGNUM(UXSTACKTOP - PGSIZE)) )
					continue;

				/* COW */
				err = duppage(envid, pn);
				if (err) {
					envid = (envid_t)err;
					goto out;
				}
			}
		}

		// (4) - set up page fault handling - code identical to set_pgfault_handler()
		err = sys_page_alloc(envid, (void *)(UXSTACKTOP - PGSIZE), (PTE_W | PTE_U | PTE_P));
		if ( !err ) {
			err = sys_env_set_pgfault_upcall(envid, thisenv->env_pgfault_upcall);
		}
		if (err != 0) {
			envid = (envid_t)err;
			goto out;
		}

		// (5) - green light
		sys_env_set_status(envid, ENV_RUNNABLE);
	}

out:
	return envid;
}

/*
 * fork a 'thread' 
 * processes with (mainly) shared memory 
 * Note: 
 * sfork() is 100% identical to fork(), 
 * except a single point in code where it distinguishes 
 * where to COW and where to share. 
 * TODO: 
 * unify fork() and sfork() under clone() function that would accept 'share_or_cow' flag
 */
int
sfork(void)
{
	envid_t envid;
	unsigned pdi;
	unsigned pti;
	unsigned pn;
	int err;

	// (1)
	set_pgfault_handler(pgfault);
	// (2)
	envid = sys_exofork();
	if (envid == 0) {
		/* child process */
		/* fix 'thisenv' */
		thisenv = &envs[ENVX(sys_getenvid())];
	}
	else if (envid > 0) {
		/* parent process */
		/* complete configuration */
		// (3)
		// traverse all mapped pages
		for (pdi = 0; pdi < PDX(UTOP); ++pdi) {
			if ( !(uvpd[pdi] & PTE_P) )
				continue;

			for (pti = 0; pti < NPTENTRIES; ++pti) {
				pn = PGNUM(PGADDR(pdi, pti, 0));
				/* 
				 * skip non-existent pages 
				 * OR exception stack, which is allocated separately 
				 */
				if ( !(uvpt[pn] & PTE_P) || (pn == PGNUM(UXSTACKTOP - PGSIZE)) )
					continue;

				/* COW stack */
				if (pn == PGNUM(USTACKTOP - PGSIZE)) {
					err = duppage(envid, pn);
					if (err) {
						envid = (envid_t)err;
						goto out;
					}

					continue;
				}

				/* share memory */
				err = share_page(envid, pn);
				if (err) {
					envid = (envid_t)err;
					goto out;
				}
			}
		}

		// (4) - set up page fault handling - code identical to set_pgfault_handler()
		err = sys_page_alloc(envid, (void *)(UXSTACKTOP - PGSIZE), (PTE_W | PTE_U | PTE_P));
		if ( !err ) {
			err = sys_env_set_pgfault_upcall(envid, thisenv->env_pgfault_upcall);
		}
		if (err != 0) {
			envid = (envid_t)err;
			goto out;
		}

		// (5) - green light
		sys_env_set_status(envid, ENV_RUNNABLE);
	}

out:
	return envid;
}

