#include <unistd.h>
#include <sys/statfs.h>

#include "../x86/__syscall.h"

int statfs(const char *path, struct statfs *buf)
{
	return syscall3(SYS_statfs64, (long) path, sizeof(*buf), (long) buf);
}