#include <stdlib.h>
#include <string.h>

#include "mem.h"

void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (!ret)
		exit(1);

	return ret;
}

void *xrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if (!ret)
		exit(1);

	return ret;
}

char *xstrdup(const char *s)
{
	char *ret = strdup(s);
	if (!ret)
		exit(1);

	return ret;
}

char *xstrndup(const char *s, size_t n)
{
	char *ret = strndup(s, n);
	if (!ret)
		exit(1);

	return ret;
}
