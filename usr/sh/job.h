#ifndef _SH_JOB_H_
#define _SH_JOB_H_

#include <limits.h>
#include <stdbool.h>

#include "readline.h"

#define NR_JOBS			32

/*
 * Job.
 */
struct job {
	int		id;			/* job id */
	pid_t		pid;			/* job pid */
	char *		cmdline;		/* command line */
	int		argc;			/* number of arguments */
	char *		argv[ARG_MAX];		/* arguments */
	int		fd_in;			/* input fd */
	int		fd_out;			/* output fd */
	bool		bg;			/* background job ? */
};

/* job table */
extern struct job job_table[NR_JOBS];

int job_submit(char *cmdline, struct rline_ctx *ctx);
void job_free(struct job *job);

#endif