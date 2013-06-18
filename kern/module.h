#ifndef JOS_KERN_MODULE_H
#define JOS_KERN_MODULE_H

#define MODULE_NAME_MAXLEN	32

typedef struct {
	char		mod_name[MODULE_NAME_MAXLEN];
	uintptr_t	mod_addr;
	size_t		mod_size;
	int (*init_module)(void);
	void (*cleanup_module)(void);

} KModInfo;


int module_init(KModInfo *info);
int module_cleanup(const char *name);

#endif	// JOS_KERN_MODULE_H

