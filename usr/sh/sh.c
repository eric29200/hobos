#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pwd.h>
#include <time.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "../libutils/libutils.h"
#include "readline.h"
#include "job.h"
#include "utils.h"

#define USERNAME_SIZE		1024
#define HOSTNAME_SIZE		256

static char username[USERNAME_SIZE];
static char hostname[HOSTNAME_SIZE];
static char cwd[PATH_MAX];

/*
 * Init prompt values.
 */
static void init_prompt_values()
{
	struct passwd *passwd;
	uid_t uid;
	char *s;

	/* reset values */
	memset(username, 0, USERNAME_SIZE);
	memset(hostname, 0, HOSTNAME_SIZE);
	memset(cwd, 0, PATH_MAX);

	/* get hostname */
	gethostname(hostname, HOSTNAME_SIZE - 1);

	/* get user from env */
	s = getenv("USER");
	if (s) 
		return;

	/* get passwd */
	uid = geteuid();
	passwd = getpwuid(uid);
	if (passwd)
		strncpy(username, passwd->pw_name, USERNAME_SIZE);
	else
		snprintf(username, USERNAME_SIZE, "%d", uid);
}

/*
 * Execute a command line.
 */
static int execute_cmdline(struct rline_ctx *ctx, char *cmd_line)
{
	int nr_cmds, i, ret = 0;
	char *cmds[ARG_MAX];
	struct job *job;

	/* parse commands */
	nr_cmds = tokenize(cmd_line, cmds, ARG_MAX, ";");

	/* execute commands */
	for (i = 0; i < nr_cmds; i++) {
		/* create job */
		job = job_create(cmds[i]);
		if (!job) {
			ret = -1;
			continue;
		}

		/* execute job */
		ret |= job_execute(job, ctx);

		/* free job */
		job_free(job);
	}

	return ret;
}

/*
 * SIGINT handler.
 */
static void sigint_handler()
{
	printf("\n");
	fflush(stdout);
}

/*
 * Interactive shell.
 */
static int sh_interactive()
{
	char *cmd_line = NULL;
	struct rline_ctx ctx;
	struct tm *tm;
	time_t t;

	/* install signal handlers */
	if (signal(SIGINT, sigint_handler))
		perror("SIGINT");

	/* init prompt */
	init_prompt_values();

	/* init readline context */
	rline_init_ctx(&ctx);

	for (;;) {
		/* get current working directory */
		memset(cwd, 0, PATH_MAX);
		getcwd(cwd, PATH_MAX);

		/* get current time */
		time(&t);
		tm = localtime(&t);

		/* print prompt */
		printf("[%02d:%02d]\33[1m%s\33[0m@%s:\33[1m%s\33[0m>", tm->tm_hour, tm->tm_min, username, hostname, cwd);
		fflush(stdout);

		/* get next command */
		if (rline_readline(&ctx, &cmd_line) <= 0)
			continue;

		/* execute command */
		execute_cmdline(&ctx, cmd_line);
	}

	/* free command line */
	if (cmd_line)
		free(cmd_line);

	/* exit readline context */
	rline_exit_ctx(&ctx);

	return 0;
}

/*
 * Execute shell script.
 */
static int sh_script(const char *filename)
{
	char *cmd_line = NULL;
	size_t n = 0;
	ssize_t len;
	FILE *fp;

	/* open input file */
	fp = fopen(filename, "r");
	if (!fp) {
		perror(filename);
		return -1;
	}

	/* execute each line */
	while ((len = getline(&cmd_line, &n, fp)) > 0) {
		/* remove last eol */
		if (cmd_line[len - 1] == '\n')
			cmd_line[len - 1] = 0;

		/* execute command */
		execute_cmdline(NULL, cmd_line);
	}

	/* free command line */
	if (cmd_line)
		free(cmd_line);

	/* close input file */
	fclose(fp);

	return 0;
}

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

	/* no argument : interactive shell */
	if (!argc)
		return sh_interactive();
	else
		return sh_script(*argv);
}
