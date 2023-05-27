#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/wait.h>

#include "job.h"
#include "redir.h"
#include "cmd.h"
#include "alias.h"
#include "utils.h"


/* job table */
struct job job_table[NR_JOBS] = { 0 };
struct job main_job;

/*
 * Free a job.
 */
void job_free(struct job *job)
{
	if (job) {
		if (job->cmdline)
			free(job->cmdline);

		if (job->fd_in >= 0 && job->fd_in != STDIN_FILENO)
			close(job->fd_in);

		if (job->fd_out >= 0 && job->fd_out != STDOUT_FILENO)
			close(job->fd_out);

		memset(job, 0, sizeof(struct job));
		job->pid = -1;
	}
}

/*
 * Make command line and arguments.
 */
static int job_make_args(struct job *job, char *cmdline)
{
	char *s0, *e0, *argv0;
	bool has_arg = false;
	struct alias *alias;
	size_t len0, lenr;

	/* get argv[0] */
	for (s0 = cmdline; *s0 && isspace(*s0); s0++);
	for (e0 = s0; *e0 && !isspace(*e0); e0++);

	/* end argv[0] */
	if (isspace(*e0)) {
		has_arg = true;
		*e0 = 0;
	}

	/* use alias instead of argv[0] */
	alias = alias_find(s0);
	if (alias)
		argv0 = alias->value;
	else
		argv0 = s0;

	/* allocate command line */
	len0 = strlen(argv0);
	lenr = has_arg ? strlen(e0 + 1) : 0;
	job->cmdline = (char *) malloc(len0 + lenr + 2);
	if (!job->cmdline)
		return -1;

	/* concat argv[0] + ' ' + remaining arguments */
	memcpy(job->cmdline, argv0, len0);
	job->cmdline[len0] = ' ';
	memcpy(job->cmdline + len0 + 1, e0 + 1, lenr);
	job->cmdline[len0 + lenr + 1] = 0;

	/* parse arguments */
	job->argc = make_args(job->cmdline, job->argv, ARG_MAX);

	return 0;
}

/*
 * Execute a job.
 */
static int job_execute(struct job *job, struct rline_ctx *ctx)
{
	sigset_t set, set_old;
	int ret, status;
	pid_t pid;

	/* try builtin commands */
	if (cmd_builtin(ctx, job->argc, job->argv, &ret) == 0) {
		job_free(job);
		return 0;
	}

	/* block signals during fork */
	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigprocmask(SIG_BLOCK, &set, &set_old);

	/* fork */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}

	/* child process */
	if (pid == 0) {
		/* redirect stdin */
		if (job->fd_in != STDIN_FILENO) {
			dup2(job->fd_in, STDIN_FILENO);
			close(job->fd_in);
		}

		/* redirect stdout */
		if (job->fd_out != STDOUT_FILENO) {
			dup2(job->fd_out, STDOUT_FILENO);
			close(job->fd_out);
		}

		/* execute command */
		ret = execvpe(job->argv[0], job->argv, environ);
		if (ret < 0)
			perror(job->argv[0]);

		/* exit child */
		exit(ret);
		return ret;
	}

	/* restore signals */
	sigprocmask(SIG_SETMASK, &set_old, NULL);

	/* set job pid */
	job->pid = pid;

	/* wait for child and free job */
	if (!job->bg) {
		while ((ret = waitpid(job->pid, &status, 0)) == 0);

		/* no matching child : sigchld probably got it */
		if (ret < 0 && errno != ECHILD)
			perror("waitpid");

		/* free job */
		job_free(job);
	}

	return ret;
}
 
/*
 * Submit a job.
 */
int job_submit(char *cmdline, struct rline_ctx *ctx)
{
	struct job *job = &main_job;
	int len, i;
	char *s;

	/* empty command line */
	len = strlen(cmdline);
	if (!len)
		return 0;

	/* background job */
	for (s = cmdline + len - 1; len >= 0; len--, s--)
		if (!isspace(*s))
			break;

	/* background job */
	if (*s == '&') {
		/* remove ending "&" */
		*s = 0;

		/* find a free job */
		for (i = 0; i < NR_JOBS; i++)
			if (!job_table[i].id)
				break;

		/* no free job */
		if (i >= NR_JOBS)
			return -1;

		/* set job */
		job = &job_table[i];
		job->id = i + 1;
		job->bg = 1;

	}

	/* input redirection */
	job->fd_in = redir_input(cmdline);
	if (job->fd_in < 0)
		goto err;

	/* output redirection */
	job->fd_out = redir_output(cmdline);
	if (job->fd_out < 0)
		goto err;

	/* make arguments */
	if (job_make_args(job, cmdline))
		goto err;

	/* no arguments */
	if (!job->argc) {
		job_free(job);
		return 0;
	}

	/* execute job */
	return job_execute(job, ctx);
err:
	job_free(job);
	return -1;
}
