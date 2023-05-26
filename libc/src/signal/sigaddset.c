#include <signal.h>
#include <errno.h>

int sigaddset(sigset_t *set, int signum)
{
	unsigned s = signum - 1;

	if (s >= NSIG - 1 || signum - 32U < 3) {
		errno = EINVAL;
		return -1;
	}

	*set |= (1 << signum);
	return 0;
}