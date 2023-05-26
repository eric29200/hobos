#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include "../x86/__syscall.h"

int sigprocmask(int how, const sigset_t *set, sigset_t *old)
{
	if (set && (unsigned) how - SIG_BLOCK > 2U)
		return __syscall_ret(-EINVAL);

	return syscall4(SYS_rt_sigprocmask, how, (long) set, (long) old, NSIG / 8);
}