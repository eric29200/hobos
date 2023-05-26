#include <signal.h>

int sigismember(const sigset_t *set, int signum)
{
	unsigned s = signum - 1;
	
	if (s >= NSIG - 1 || signum - 32U < 3)
		return 0;

	return 1 & (*set >> signum);
}