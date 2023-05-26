#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <pwd.h>

#include "readline.h"
#include "alias.h"
#include "job.h"

/*
 * Get home directory.
 */
static int get_homedir(char *buf, size_t len)
{
	struct passwd *passwd;
	uid_t uid;
	char *s;

	/* get home from env */
	s = getenv("HOME");
	if (s) {
		strncpy(buf, s, len);
		return 0;
	}

	/* get passwd */
	uid = geteuid();
	passwd = getpwuid(uid);
	if (!passwd)
		return -1;

	/* set homedir */
	strncpy(buf, passwd->pw_dir, len);
	return 0;
 }

/*
 * Change dir command.
 */
static int cmd_cd(int argc, char **argv)
{
	char homedir[PATH_MAX], *path;

	/* use argument or home directory */
	if (argc > 1) {
		path = argv[1];
	} else {
		get_homedir(homedir, PATH_MAX);
		path = homedir;
	}

	/* change directory */
	if (chdir(path) < 0) {
		perror(path);
		return -1;
	}

	return 0;
}

/*
 * History command.
 */
static int cmd_history(struct rline_ctx *ctx, int argc, char **argv)
{
	size_t i = ctx->history_size;
	struct tm *tm;

	if (!ctx)
		return -1;

	/* number of lines to print */
	if (argc > 1) {
		i = atoi(argv[1]);
		if (i > ctx->history_size)
			i = ctx->history_size;
	}

	/* print history */
	for (i = ctx->history_size - i; i < ctx->history_size; i++) {
		tm = localtime(&ctx->history[i]->time);
		printf("%d\t%02d:%02d\t%s\n", i + 1, tm->tm_hour, tm->tm_min, ctx->history[i]->line);
	}

	return 0;
}

/*
 * Jobs command.
 */
static int cmd_jobs()
{
	int i;

	for (i = 0; i < NR_JOBS; i++)
		if (job_table[i].id)
			printf("[%d]\t%s\n", job_table[i].id, job_table[i].cmdline);

	return 0;
}
 
/*
 * Execute builtin command.
 */
int cmd_builtin(struct rline_ctx *ctx, int argc, char **argv, int *status)
{
	/* exit command */
	if (strcmp(argv[0], "exit") == 0)
		exit(0);

	/* cd command */
	if (strcmp(argv[0], "cd") == 0) {
		*status = cmd_cd(argc, argv);
		return 0;
	}

	/* history command */
	if (strcmp(argv[0], "history") == 0) {
		*status = cmd_history(ctx, argc, argv);
		return 0;
	}

	/* alias command */
	if (strcmp(argv[0], "alias") == 0) {
		*status = cmd_alias(argc, argv);
		return 0;
	}

	/* unalias command */
	if (strcmp(argv[0], "unalias") == 0) {
		*status = cmd_unalias(argc, argv);
		return 0;
	}

	/* jobs command */
	if (strcmp(argv[0], "jobs") == 0) {
		*status = cmd_jobs();
		return 0;
	}

	return -1;
}
