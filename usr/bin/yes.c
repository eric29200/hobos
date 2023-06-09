#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "../libutils/libutils.h"

/* options */
struct option long_opts[] = {
	{ "help",	no_argument,	0,	OPT_HELP	},
	{ 0,		0,		0,	0		},
};

/*
 * Usage.
 */
static void usage(const char *name)
{
	fprintf(stderr, "Usage: %s [message]\n", name);
	fprintf(stderr, "      , --help        print help and exit\n");
}

int main(int argc, char **argv)
{
	const char *name = argv[0];
	char *yes = "y";
	int c;

	/* get options */
	while ((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
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

	if (argc)
		yes = *argv;

	for (;;)
		printf("%s\n", yes);

	return 0;
}
