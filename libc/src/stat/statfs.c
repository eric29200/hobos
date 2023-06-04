#include <unistd.h>
#include <sys/statfs.h>

#include "../x86/__syscall.h"

int statfs(const char *path, struct statfs *buf)
{
	return syscall2(SYS_statfs64, (long) path, (long) buf);
}