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
#include "../libreadline/readline.h"
#include "pipeline.h"
#include "utils.h"
#include "job.h"

#define HISTORY_SIZE		50
#define USERNAME_SIZE		1024
#define HOSTNAME_SIZE		256

static char username[USERNAME_SIZE];
static char hostname[HOSTNAME_SIZE];
static char cwd[PATH_MAX];
static char homedir[PATH_MAX];

/*
 * Init prompt values.
 */
static void init_prompt_values()
{
	bool user_set = false, home_set = false;
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
	if (s) {
		strncpy(username, s, USERNAME_SIZE);
		user_set = true;
	}

	/* get user from env */
	s = getenv("HOME");
	if (s) {
		strncpy(homedir, s, PATH_MAX);
		home_set = true;
	}

	/* get passwd */
	if (!user_set || !home_set) {
		/* get passwd */
		uid = geteuid();
		passwd = getpwuid(uid);

		/* set user */
		if (!user_set) {
			if (passwd)
				strncpy(username, passwd->pw_name, USERNAME_SIZE);
			else
				snprintf(username, USERNAME_SIZE, "%d", uid);
		}

		/* set homedir */
		if (!home_set) {
		 	if (passwd)
				strncpy(homedir, passwd->pw_dir, PATH_MAX);
			else
				strncpy(homedir, "/", PATH_MAX);
		}
	}
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
 * SIGCHLD handler.
 */
static void sigchld_handler()
{
	int status, i;
	pid_t pid;

	/* get terminated process */
	pid = waitpid(-1, &status, 1);

	/* free matching job */
	for (i = 0; i < NR_JOBS; i++) {
		if (job_table[i].pid == pid) {
			/* print ending message */
			printf("[%d]\tDone\t%s\n", job_table[i].id, job_table[i].cmdline);

			/* free job */
			job_free(&job_table[i]);
		}
	}
}

/*
 * Interactive shell.
 */
static int sh_interactive()
{
	char *cmd_line = NULL;
	struct pipeline line;
	struct rline_ctx ctx;
	struct tm *tm;
	time_t t;

	/* reset pipeline */
	memset(&line, 0, sizeof(struct pipeline));

	/* install signal handlers */
	if (signal(SIGINT, sigint_handler))
		perror("SIGINT");
	if (signal(SIGCHLD, sigchld_handler))
		perror("SIGINT");

	/* init readline context */
	rline_init_ctx(&ctx, HISTORY_SIZE);

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

		/* parse/execute command line */
		if (pipeline_parse(&line, cmd_line) == 0)
			pipeline_execute(&line, &ctx);

		/* clear pipeline */
		pipeline_clear(&line);
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
	struct pipeline line;
	size_t n = 0;
	ssize_t len;
	FILE *fp;

	/* reset pipeline */
	memset(&line, 0, sizeof(struct pipeline));

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

		/* parse/execute command line */
		if (pipeline_parse(&line, cmd_line) == 0)
			pipeline_execute(&line, NULL);

		/* clear pipeline */
		pipeline_clear(&line);
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
	char path[PATH_MAX];
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

	/* init prompt */
	init_prompt_values();

	/* load .shrc */
	if (build_path(homedir, ".shrc", path, PATH_MAX) == 0)
		sh_script(path);

	/* no argument : interactive shell */
	if (!argc)
		return sh_interactive();
	else
		return sh_script(*argv);
}
