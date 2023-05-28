#include <unistd.h>

#include "../x86/__syscall.h"

int setuid(uid_t uid)
{
	return syscall1(SYS_setuid, uid);
}