#include <inc/string.h>

#include "fs.h"

static void mark_block_free(uint32_t blockno);
static void mark_block_used(uint32_t blockno);

// --------------------------------------------------------------
// Super block
// --------------------------------------------------------------

// Validate the file system super-block.
void
check_super(void)
{
	if (super->s_magic != FS_MAGIC)
		panic("bad file system magic number");

	if (super->s_nblocks > DISKSIZE/BLKSIZE)
		panic("file system is too large");

	cprintf("superblock is good\n");
}


// --------------------------------------------------------------
// File system structures
// --------------------------------------------------------------

// Initialize the file system
void
fs_init(void)
{
	static_assert(sizeof(struct File) == 256);

	// Find a JOS disk.  Use the second IDE disk (number 1) if available.
	if (ide_probe_disk1())
		ide_set_disk(1);
	else
		ide_set_disk(0);

	bc_init();

	// Set "super" to point to the super block.
	super = diskaddr(1);

	// Set 'bitmap' ...
	bitmap = diskaddr(2);

	check_super();
}

// Find the disk block number slot for the 'filebno'th block in file 'f'.
// Set '*ppdiskbno' to point to that slot.
// The slot will be one of the f->f_direct[] entries,
// or an entry in the indirect block.
// When 'alloc' is set, this function will allocate an indirect block
// if necessary.
//
// Returns:
//	0 on success (but note that *ppdiskbno might equal 0).
//	-E_NOT_FOUND if the function needed to allocate an indirect block, but
//		alloc was 0.
//	-E_NO_DISK if there's no space on the disk for an indirect block.
//	-E_INVAL if filebno is out of range (it's >= NDIRECT + NINDIRECT).
//
// Analogy: This is like pgdir_walk for files.
// Hint: Don't forget to clear any block you allocate.
static int
file_block_walk(struct File *f, uint32_t filebno, uint32_t **ppdiskbno, bool alloc)
{
	int r;
	uint32_t *ptr;


	if (filebno < NDIRECT) {
		ptr = &f->f_direct[filebno];
	}
	else if (filebno < NDIRECT + NINDIRECT) {
		if (f->f_indirect == 0) {
			if ( !alloc )
				return -E_NOT_FOUND;

			/* allocate indirect block */
			f->f_indirect = alloc_block();
			if ( !f->f_indirect )
				return -E_NO_DISK;
			memset(diskaddr(f->f_indirect), 0, BLKSIZE);
		}
		ptr = &((uint32_t*)diskaddr(f->f_indirect))[filebno - NDIRECT];
	}
	else {
		cprintf("%s: block number out of range: %u \n", __FUNCTION__, filebno);
		*ppdiskbno = NULL;
		return -E_INVAL;
	}

	*ppdiskbno = ptr;
	return 0;
}

// Set *blk to the address in memory where the filebno'th
// block of file 'f' would be mapped.
//
// Returns 0 on success, < 0 on error.  Errors are:
//	-E_NO_DISK if a block needed to be allocated but the disk is full.
//	-E_INVAL if filebno is out of range.
//
int
file_get_block(struct File *f, uint32_t filebno, char **blk)
{
	int r;
	uint32_t *ptr;

	if ((r = file_block_walk(f, filebno, &ptr, 1)) < 0)
		return r;

	/* allocate indirect block */
	if (*ptr == 0) {
		*ptr = alloc_block();
		if (*ptr == 0)
			return -E_NO_DISK;
	}

	*blk = diskaddr(*ptr);
	return 0;
}

static int
file_free_block(struct File *f, uint32_t linblock)
{
	int r;
	uint32_t *block_ptr;

	r = file_block_walk(f, linblock, &block_ptr, false);
	if (r)
		return r;

	if (*block_ptr != 0) {
		mark_block_free(*block_ptr);
		*block_ptr = 0;
	}

	return 0;
}

// Try to find a file named "name" in dir.  If so, set *file to it.
//
// Returns 0 and sets *file on success, < 0 on error.  Errors are:
//	-E_NOT_FOUND if the file is not found
static int
dir_lookup(struct File *dir, const char *name, struct File **file)
{
	int r;
	uint32_t i, j, nblock;
	char *blk;
	struct File *f;

	// Search dir for name.
	// We maintain the invariant that the size of a directory-file
	// is always a multiple of the file system's block size.
	assert((dir->f_size % BLKSIZE) == 0);
	nblock = dir->f_size / BLKSIZE;
	for (i = 0; i < nblock; i++) {
		if ((r = file_get_block(dir, i, &blk)) < 0)
			return r;
		f = (struct File*) blk;
		for (j = 0; j < BLKFILES; j++)
			if (strcmp(f[j].f_name, name) == 0) {
				*file = &f[j];
				return 0;
			}
	}
	return -E_NOT_FOUND;
}


// Skip over slashes.
static const char*
skip_slash(const char *p)
{
	while (*p == '/')
		p++;
	return p;
}

// Evaluate a path name, starting at the root.
// On success, set *pf to the file we found
// and set *pdir to the directory the file is in.
// If we cannot find the file but find the directory
// it should be in, set *pdir and copy the final path
// element into lastelem.
static int
walk_path(const char *path, struct File **pdir, struct File **pf, char *lastelem)
{
	const char *p;
	char name[MAXNAMELEN];
	struct File *dir, *f;
	int r;

	// if (*path != '/')
	//	return -E_BAD_PATH;
	path = skip_slash(path);
	f = &super->s_root;
	dir = 0;
	name[0] = 0;

	if (pdir)
		*pdir = 0;
	*pf = 0;
	while (*path != '\0') {
		dir = f;
		p = path;
		while (*path != '/' && *path != '\0')
			path++;
		if (path - p >= MAXNAMELEN)
			return -E_BAD_PATH;
		memmove(name, p, path - p);
		name[path - p] = '\0';
		path = skip_slash(path);

		if (dir->f_type != FTYPE_DIR)
			return -E_NOT_FOUND;

		if ((r = dir_lookup(dir, name, &f)) < 0) {
			if (r == -E_NOT_FOUND && *path == '\0') {
				if (pdir)
					*pdir = dir;
				if (lastelem)
					strcpy(lastelem, name);
				*pf = 0;
			}
			return r;
		}
	}

	if (pdir)
		*pdir = dir;
	*pf = f;
	return 0;
}

// --------------------------------------------------------------
// File operations
// --------------------------------------------------------------


// Open "path".  On success set *pf to point at the file and return 0.
// On error return < 0.
int
file_open(const char *path, struct File **pf)
{
	return walk_path(path, 0, pf, 0);
}

int
file_create(const char *path, struct File **f)
{
	int r;
	struct File *dir;
	char filename[MAXNAMELEN];

	r = walk_path(path, &dir, f, filename);
	if (r == 0) {
		/* open existing file */
		return 0;
	}

	cprintf("TODO: support creating new files \n");
	return -E_NOT_SUPP;
}



/** 
 * Set effective file size by setting its offset and, possibly,
 * size.
 */ 
int
file_set_size(struct File *f, off_t newsize)
{
	uint32_t start_block;
	uint32_t stop_block;
	uint32_t n;

	if (newsize < f->f_size) {
		start_block = (newsize + BLKSIZE - 1) / BLKSIZE;
		stop_block = (f->f_size + BLKSIZE - 1) / BLKSIZE;
		for (n = start_block; n < stop_block; ++n) {
			file_free_block(f, n);
		}

		if ((start_block <= NDIRECT) && (stop_block > NDIRECT)) {
			mark_block_free(f->f_indirect);
			f->f_indirect = 0;
		}
	}

	f->f_size = newsize;
	return 0;
}

// Read count bytes from f into buf, starting from seek position
// offset.  This meant to mimic the standard pread function.
// Returns the number of bytes read, < 0 on error.
ssize_t
file_read(struct File *f, void *buf, size_t count, off_t offset)
{
	int r, bn;
	off_t pos;
	char *blk;

	if (offset >= f->f_size)
		return 0;

	count = MIN(count, f->f_size - offset);

	for (pos = offset; pos < offset + count; ) {
		if ((r = file_get_block(f, pos / BLKSIZE, &blk)) < 0)
			return r;
		bn = MIN(BLKSIZE - pos % BLKSIZE, offset + count - pos);
		memmove(buf, blk + pos % BLKSIZE, bn);
		pos += bn;
		buf += bn;
	}

	return count;
}



/**
 * Write bytes to a file, extending it as necessary
 * @return the number of bytes written or negative error code
 */
int
file_write(struct File *f, const void *buf, size_t count, off_t offset)
{
	int r, bn;
	off_t pos;
	char *blk;

	/* extend as necessary */
	if ((offset + count) > f->f_size) {
		r = file_set_size(f, (offset + count));
		if (r)
			return r;
	}

	for (pos = offset; pos < offset + count; ) {
		if ((r = file_get_block(f, pos / BLKSIZE, &blk)) < 0)
			return r;
		bn = MIN(BLKSIZE - pos % BLKSIZE, offset + count - pos);
		memmove(blk + pos % BLKSIZE, buf, bn);
		pos += bn;
		buf += bn;
	}

	return count;
}



static bool
bitmap_get_bit_value(uint32_t blockno)
{
	return (bitmap[blockno / 32] & (1 << (blockno % 32))) != 0;
}

static void
bitmap_set_bit_value(uint32_t blockno, bool value)
{
	bitmap[blockno / 32] &= ~(1 << (blockno % 32));
	bitmap[blockno / 32] |= (value << (blockno % 32));
}



bool
block_is_free(uint32_t blockno)
{
	if ((super == NULL) || (blockno > super->s_nblocks)) {
		cprintf("trying to access filesystem block out of range: %u \n", blockno);
		return false;
	}

	return bitmap_get_bit_value(blockno);
}

static void
mark_block_free(uint32_t blockno)
{
	panic_if((blockno == 0), "zero block fault");
	bitmap_set_bit_value(blockno, true);
}

static void
mark_block_used(uint32_t blockno)
{
	panic_if((blockno == 0), "zero block fault");
	bitmap_set_bit_value(blockno, false);
}

int
alloc_block(void)
{
	int n;

	for (n = 1; n < super->s_nblocks; ++n) {
		if (block_is_free(n)) {
			mark_block_used(n);
			return n;
		}
	}

	return 0;
}

