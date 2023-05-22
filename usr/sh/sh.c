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
#include <sys/wait.h>

#include "../libutils/libutils.h"
#include "readline.h"

#define USERNAME_SIZE		1024
#define HOSTNAME_SIZE		256

static char username[USERNAME_SIZE];
static char hostname[HOSTNAME_SIZE];
static char homepath[PATH_MAX];
static char cwd[PATH_MAX];

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
	memset(homepath, 0, PATH_MAX);
	memset(cwd, 0, PATH_MAX);

	/* get user from env */
	s = getenv("USER");
	if (s) {
		strncpy(username, s, USERNAME_SIZE);
		user_set = true;
	}

	/* get home from env */
	s = getenv("HOME");
	if (s) {
		strncpy(homepath, s, PATH_MAX);
		home_set = true;
	}

	/* get passwd */
	if (!user_set || !home_set) {
		uid = geteuid();
		passwd = getpwuid(uid);

		if (passwd && !user_set) {
			strncpy(username, passwd->pw_name, USERNAME_SIZE);
			user_set = true;
		}

		if (passwd && !home_set) {
			strncpy(homepath, passwd->pw_dir, PATH_MAX);
			home_set = true;
		}
	}

	/* else user uid */
	if (!user_set)
		snprintf(username, USERNAME_SIZE, "%d", uid);

	/* get hostname */
	gethostname(hostname, HOSTNAME_SIZE - 1);
}

/*
 * Exit command.
 */
static int __cmd_exit()
{
	exit(0);

	return 0;
}

/*
 * Change dir command.
 */
static int __cmd_cd(int argc, char **argv)
{
	char *path = argc > 1 ? argv[1] : homepath;
	int ret;

	ret = chdir(path);
	if (ret < 0) {
		perror(path);
		return 1;
	}

	return 0;
}

/*
 * Execute a command.
 */
static int execute_cmd(char *cmd_line)
{
	int argc = 0, ret = 0, status;
	char *argv[ARG_MAX], *arg;
	pid_t pid;

	/* parse arguments */
	arg = strtok(cmd_line, " ");
	while (arg) {
		argv[argc++] = arg;
		arg = strtok(NULL, " ");
	}

	/* arguments must be NULL terminated */
	argv[argc] = NULL;

	/* builtin commands */
	if (strcmp(argv[0], "exit") == 0)
		return __cmd_exit();
	else if (strcmp(argv[0], "cd") == 0)
		return __cmd_cd(argc, argv);

	/* fork */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		ret = 1;
	} else if (pid == 0) {
		/* execute command */
		ret = execvpe(argv[0], argv, environ);
		if (ret < 0)
			perror(argv[0]);

		/* exit child */
		exit(ret);
	} else {
		/* wait for whild */
		if (waitpid(pid, &status, 0) < 0)
			perror("waitpid");
	}

	return ret;
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

	/* init prompt */
	init_prompt_values();

	/* init readline context */
	rline_init_ctx(&ctx);

	for (;;) {
		/* get current working directory */
		getcwd(cwd, PATH_MAX);

		/* get current time */
		time(&t);
		tm = localtime(&t);

		/* print prompt */
		printf("[%02d:%02d]\33[1m%s\33[0m@%s:\33[1m%s\33[0m> ", tm->tm_hour, tm->tm_min, username, hostname, cwd);
		fflush(stdout);

		/* get next command */
		if (rline_read_line(&ctx, &cmd_line) <= 0)
			continue;

		/* execute command */
		execute_cmd(cmd_line);
	}

	/* exit readline context */
	rline_exit_ctx(&ctx);

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

	/* check arguments */
	if (argc) {
		usage(name);
		exit(1);
	}

	return sh_interactive();
}
