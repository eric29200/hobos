#ifndef _SH_JOB_H_
#define _SH_JOB_H_

#include <limits.h>

#include "readline.h"

/*
 * Job.
 */
struct job {
	char *		cmdline;		/* command line */
	int		argc;			/* number of arguments */
	char *		argv[ARG_MAX];		/* arguments */
	int		fd_in;			/* input fd */
	int		fd_out;			/* output fd */
};


struct job *job_create(char *cmdline);
void job_free(struct job *job);
int job_execute(struct job *job, struct rline_ctx *ctx);

#endif