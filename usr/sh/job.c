#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "job.h"
#include "redir.h"
#include "cmd.h"
#include "utils.h"

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

		free(job);
	}
}

/*
 * Create a job.
 */
struct job *job_create(char *cmdline)
{
	struct job *job;

	/* allocate a new job */
	job = (struct job *) malloc(sizeof(struct job));
	if (!job)
		return NULL;

	/* reset job */
	memset(job, 0, sizeof(struct job));
	
	/* input redirection */
	job->fd_in = redir_input(cmdline);
	if (job->fd_in < 0)
		goto err;

	/* output redirection */
	job->fd_out = redir_output(cmdline);
	if (job->fd_out < 0)
		goto err;

	/* dup command line */
	job->cmdline = strdup(cmdline);
	if (!job->cmdline) 
		goto err;
	
	/* parse arguments */
	job->argc = make_args(job->cmdline, job->argv, ARG_MAX);

	return job;
err:
	job_free(job);
	return NULL;
}

/*
 * Execute a job.
 */
int job_execute(struct job *job, struct rline_ctx *ctx)
{
	int ret = 0, status;
	pid_t pid;

	/* try builtin commands */
	if (cmd_builtin(ctx, job->argc, job->argv, &ret) == 0)
		goto out;

	/* fork */
	pid = fork();
	if (pid < 0) {
		perror("fork");
		ret = -1;
	} else if (pid == 0) {
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

	/* wait for whild */
	while ((ret = waitpid(pid, &status, 0)) == 0);
	if (ret < 0)
		perror("waitpid");

out:
	return ret;
}