#include <inc/error.h>
#include <inc/string.h>

#include <kern/pmap.h>
#include <kern/module.h>

/*
 * Kernel Module database 
 * in current implementation hosts a single module 
 */
static KModInfo kmod_data = {{0}};


#define module_pin_memory(info)		module_pin_unpin_memory((info), 1)
#define module_unpin_memory(info)	module_pin_unpin_memory((info), 0)

static int
module_pin_unpin_memory(KModInfo *info, int pin)
{
	uintptr_t virt_addr;
	physaddr_t phys_addr;
	pte_t *pgtab_entry;
	struct PageInfo *p;

	p = page_lookup(kern_pgdir, (void *)info->mod_addr, NULL);
	if (p == NULL) {
		cprintf("BUG: trying to insert / remove a module located in unmapped memory [%s : %08x] \n", info->mod_name, info->mod_addr);
		return -E_INVAL;
	}

	if (pin) {
		++p->pp_ref;
	}
	else {
		page_decref(p);
	}

	return 0;
}

int
module_init(KModInfo *info)
{
	int ret;

	if ( kmod_data.mod_name[0] ) {
		cprintf("cannot load module '%s', limit has been reached \n", info->mod_name);
		return -E_NO_MEM;
	}

	ret = module_pin_memory(info);
	if (ret)
		return ret;

	kmod_data = *info;
	return kmod_data.init_module();
}

int
module_cleanup(const char *name)
{
	if (strcmp(name, kmod_data.mod_name)) {
		cprintf("module '%s' is not loaded \n", name);
		return -E_INVAL;
	}

	kmod_data.cleanup_module();

	module_unpin_memory(&kmod_data);
	memset(&kmod_data, 0, sizeof(KModInfo));
	return 0;
}

