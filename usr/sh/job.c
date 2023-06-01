#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "job.h"
#include "builtin.h"
#include "mem.h"

/* job table */
struct job job_table[NR_JOBS] = { 0 };

/*
 * Free a job.
 */
void job_free(struct job *job)
{
	if (job) {
		if (job->cmdline)
			free(job->cmdline);

		memset(job, 0, sizeof(struct job));
		job->pid = -1;
	}
}

/*
 * Submit a job.
 */
struct job *job_submit(struct command *command, struct rline_ctx *ctx)
{
	sigset_t set, set_old;
	struct job *job;
	int i, ret;
	pid_t pid;

	/* empty command */
	if (!command->argc)
		return NULL;

	/* try builtin command */
	if (builtin(ctx, command->argc, command->argv, &ret) == 0)
		return NULL;

	/* find a free job */
	for (i = 0; i < NR_JOBS; i++)
		if (!job_table[i].id)
			break;

	/* no free job */
	if (i >= NR_JOBS)
		return NULL;

	/* set job */
	job = &job_table[i];
	job->id = i + 1;
	job->cmdline = xstrdup(command->cmdline);
	job->bg = command->end_char == '&';

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
		job_free(job);
		return NULL;
	}

	/* child process */
	if (pid == 0) {
		/* execute command */
		ret = execvpe(command->argv[0], command->argv, environ);
		if (ret < 0)
			perror(command->argv[0]);

		/* exit child */
		exit(ret);
	}

	/* set job's pid */
	job->pid = pid;

	/* restore signals */
	sigprocmask(SIG_SETMASK, &set_old, NULL);

	return job;
}
