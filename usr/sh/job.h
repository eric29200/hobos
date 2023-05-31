#ifndef _SH_JOB_H_
#define _SH_JOB_H_

#include <stdio.h>

#define NR_JOBS			32

/*
 * Job.
 */
struct job {
	int		id;			/* job id */
	pid_t		pid;			/* job pid */
	char *		cmdline;		/* command line */
};

/* job table */
extern struct job job_table[NR_JOBS];

int job_submit(pid_t pid, char *cmdline);
void job_free(struct job *job);

#endif