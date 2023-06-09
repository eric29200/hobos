#include <sys/syscall.h>
#include <proc/sched.h>
#include <stderr.h>

/*
 * Nano sleep system call.
 */
int sys_nanosleep(const struct old_timespec_t *req, struct old_timespec_t *rem)
{
	time_t timeout;

	/* check request */
	if (req->tv_nsec < 0 || req->tv_sec < 0)
		return -EINVAL;

	/* compute delay in jiffies */
	timeout = old_timespec_to_jiffies(req) + (req->tv_sec || req->tv_nsec) + jiffies;

	/* set current state sleeping and set timeout */
	current_task->state = TASK_SLEEPING;
	current_task->timeout = timeout;

	/* reschedule */
	schedule();

	/* task interrupted before timer end */
	if (timeout > jiffies) {
		if (rem)
			jiffies_to_old_timespec(timeout - jiffies - (timeout > jiffies + 1), rem);

		return -EINTR;
	}

	return 0;
}
