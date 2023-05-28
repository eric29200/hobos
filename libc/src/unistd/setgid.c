#include <unistd.h>

#include "../x86/__syscall.h"

int setgid(gid_t gid)
{
	return syscall1(SYS_setgid, gid);
}