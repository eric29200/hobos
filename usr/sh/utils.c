#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/*
 * Concat arguments.
 */
char *concat_args(int argc, char **argv)
{
	char *buf = NULL, *s;
	size_t len = 0;
	int i;

	/* compute arguments length */
	for (i = 0; i < argc; i++)
		len += strlen(argv[i]);

	/* add spaces */
	len += argc - 1;

	/* allocate string */
	s = buf = (char *) malloc(len + 1);
	if (!buf)
		return NULL;

	/* concat args */
	while (argc-- > 0) {
		/* concat arg */
		strcpy(s, *argv);
		s += strlen(*argv++);

		/* add space */
		if (argc)
			*s++ = ' ';
	}

	/* end string */
	*s = 0;

	return buf;
}
