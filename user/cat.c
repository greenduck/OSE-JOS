#include <inc/lib.h>

char buf[8192];

void
cat(int f, char *s)
{
	long n;
	int r;

	while ((n = read(f, buf, (long)sizeof(buf))) > 0) {
		r = 0;
		while ((r = write(1, &buf[r], n)) != n) {
			panic_if((r < 0), "write error copying %s: %e", s, r);
			panic_if((r > n), "write error copying %s: bytes copied (%d) > bytes requested (%d)", s, r, n);
			n -= r;
		}
	}
	if (n < 0)
		panic("error reading %s: %e", s, n);
}

void
umain(int argc, char **argv)
{
	int f, i;

	binaryname = "cat";
	if (argc == 1)
		cat(0, "<stdin>");
	else
		for (i = 1; i < argc; i++) {
			f = open(argv[i], O_RDONLY);
			if (f < 0)
				printf("can't open %s: %e\n", argv[i], f);
			else {
				cat(f, argv[i]);
				close(f);
			}
		}
}
