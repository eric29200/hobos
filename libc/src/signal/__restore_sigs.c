#include <signal.h>
#include <unistd.h>

#include "../x86/__syscall.h"

void __restore_sigs(sigset_t *set)
{
	__syscall4(SYS_rt_sigprocmask, SIG_SETMASK, (long) set, 0, NSIG / 8);
}