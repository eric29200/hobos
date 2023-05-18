#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>

#include "libutils/opt.h"

/*
 * Usage.
 */
static void usage(const char *name)
{
	fprintf(stderr, "Usage: %s\n", name);
	fprintf(stderr, "\t  , --help\t\tprint help and exit\n");
}

/* options */
struct option long_opts[] = {
	{ "help",	no_argument,	0,	OPT_HELP	},
	{ 0,		0,		0,	0		},
};

int main(int argc, char **argv)
{
	const char *name = argv[0];
	struct passwd *pwd;
	int c, index;

	/* get options */
	while ((c = getopt_long(argc, argv, "", long_opts, &index)) != -1) {
		switch (c) {
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
	if (argc) {
		usage(name);
		exit(1);
	}

	/* get passwd */
	pwd = getpwuid(geteuid());
	if (!pwd)
		exit(1);

	/* print name */
	printf("%s\n", pwd->pw_name);

	return 0;
}
