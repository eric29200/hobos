#ifndef _SH_JOB_H_
#define _SH_JOB_H_

#include <stdio.h>
#include <stdbool.h>

#include "../libreadline/readline.h"
#include "command.h"

#define NR_JOBS			32

/*
 * Job.
 */
struct job {
	int		id;			/* job id */
	pid_t		pid;			/* job pid */
	char *		cmdline;		/* command line */
	bool		bg;			/* background job ? */
};

/* job table */
extern struct job job_table[NR_JOBS];

int job_submit(struct command *command, struct rline_ctx *ctx, struct job **ret_job);
void job_free(struct job *job);

#endif