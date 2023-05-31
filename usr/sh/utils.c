#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "alias.h"
#include "mem.h"

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
	s = buf = xmalloc(len + 1);

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

/*
 * Tokenize a string.
 */
int tokenize(char *str, char **tokens, size_t tokens_len, char *delim)
{
	size_t n = 0;
	char *token;

	token = strtok(str, delim);
	while (token && n < tokens_len) {
		tokens[n++] = token;
		token = strtok(NULL, delim);
	}

	return n;
}

/*
 * Make arguments.
 */
int make_args(char *cmd, char **argv, int arg_max)
{
	int argc;

	/* make arguments */
	argc = tokenize(cmd, argv, arg_max, " ");
	argv[argc] = NULL;

	return argc;
}