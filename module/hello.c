#include "inc/stdio.h"
#include "inc/types.h"

extern const char *(*process_user_output)(const char *s, size_t len);

static int c;
static const char *(*old_process_user_output)(const char *s, size_t len);

int sample_calc(int a, int b)
{
	return (a + b) * c;
}

static const char *transmogrify(const char *s, size_t len)
{
	size_t i;
	char c;
	static char buffer[4][32];
	static int count = 0;

	if (len > 31)
		return s;

	count = (count + 1) % 4;

	for (i = 0; i < len; ++i) {
		if ((s[i] >= 0x61) && (s[i] <= 0x7a)) {
			c = s[i] - ('a' - 'A');
		}
		else {
			c = s[i];
		}

		buffer[count][i] = c;
	}

	// against evil eye ...
	buffer[count][i] = '\0';
	return buffer[count];
}

int init_module(void)
{
	c = 4;
	cprintf("Kernel module: Hello world (%d) \n", sample_calc(5, 3));

	// 'register' module's functionality
	old_process_user_output = process_user_output;
	process_user_output = transmogrify;

	return 0;
}

void cleanup_module(void)
{
	cprintf("Kernel module: Adios world \n");
}

