#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <getopt.h>

#include "../libutils/libutils.h"

#define FLAG_IGNORECASE		(1 << 0)
#define FLAG_TELLLINE		(1 << 1)

/*
 * Search a word in a string (ignore case).
 */
static bool search_ignorecase(char *str, const char *word)
{
	const char *w;
	int lowfirst;
	size_t len;

	/* get first low character */
	lowfirst = *word;
	if (isupper(lowfirst))
		lowfirst = tolower(lowfirst);

	/* search */
	for (w = word, len = 0; *str; str++) {
		/* difference : reset length */
		if (*str != *w && tolower(*str) != tolower(*w)) {
			w = word;
			len = 0;
			continue;
		}

		/* update length and return if end of word */
		len++;
		if (!*++w)
			return true;
	}

	return false;
}

/*
 * Search a word in a string (case sensitive).
 */
static bool search_case(char *str, const char *word)
{
	size_t word_len = strlen(word);

	for (;;) {
		/* find 1st character */
		str = strchr(str, word[0]);
		if (!str)
			return false;

		/* check next characters */
		if (memcmp(str, word, word_len) == 0)
			return true;

		str++;
	}

	return false;
}

/*
 * Search a word in a string.
 */
static bool search(char *str, const char *word, int flags)
{
	if (flags & FLAG_IGNORECASE)
		return search_ignorecase(str, word);

	return search_case(str, word);
}

/*
 * Grep a word in a file.
 */
static int grep(FILE *fp, const char *word, const char *filename, int flags)
{
	char buf[BUFSIZ];
	int line = 0;
	size_t len;

	/* read all file */
	while (fgets(buf, BUFSIZ, fp)) {
		/* update line count */
		line++;

		/* line must be '\n' terminated */
		len = strlen(buf);
		if (*(buf + len - 1) != '\n')
			break;

		/* search word in line */
		if (search(buf, word, flags)) {
			/* print filename */
			printf("%s:", filename);

			/* print line number */
			if (flags & FLAG_TELLLINE)
				printf("%ld:", line);

			/* print line */
			printf("%s", buf);
		}
	}

	return 0;
}

/*
 * Usage.
 */
static void usage(const char *name)
{
	fprintf(stderr, "Usage: %s [-in] string file1 [file2 ...]\n", name);
	fprintf(stderr, "      , --help           print help and exit\n");
	fprintf(stderr, "    -i, --ignore-case    ignore case\n");
	fprintf(stderr, "    -n, --line-number    prefix each line with the line number within its input file\n");
}

/* options */
struct option long_opts[] = {
	{ "help",		no_argument,	0,	OPT_HELP	},
	{ "ignore-case",	no_argument,	0,	'i'		},
	{ "line-number",	no_argument,	0,	'n'		},
	{ 0,			0,		0,	0		},
};

int main(int argc, char **argv)
{
	const char *name = argv[0];
	int flags = 0, ret, c;
	char *word;
	FILE *fp;

	/* get options */
	while ((c = getopt_long(argc, argv, "in", long_opts, NULL)) != -1) {
		switch (c) {
			case 'i':
				flags |= FLAG_IGNORECASE;
				break;
			case 'n':
				flags |= FLAG_TELLLINE;
				break;
			case OPT_HELP:
				usage(name);
				exit(0);
				break;
			default:
				exit(1);
				break;
		}
	}

	/* skip options */
	argc -= optind;
	argv += optind;

	/* check arguments */
	if (!argc) {
		usage(name);
		exit(1);
	}

	/* get word */
	word = *argv++;
	argc--;

	/* grep stdin */
	if (!argc)
		return grep(stdin, word, "stdin", flags);

	/* grep in all files */
	while (argc-- > 0) {
		/* open file */
		fp = fopen(*argv, "r");
		if (!fp) {
			perror(*argv);
			return 1;
		}

		/* grep file */
		ret = grep(fp, word, *argv++, flags);

		/* close file */
		fclose(fp);

		/* exit on error */
		if (ret)
			return ret;
	}

	return 0;
}
