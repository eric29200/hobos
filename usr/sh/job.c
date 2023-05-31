#include <stdlib.h>
#include <string.h>

#include "job.h"
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
int job_submit(pid_t pid, char *cmdline)
{
	struct job *job;
	int i;

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
	job->pid = pid;
	job->cmdline = xstrdup(cmdline);

	return 0;
}
