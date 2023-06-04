#include <unistd.h>
#include <sys/statfs.h>

#include "../x86/__syscall.h"

int fstatfs(int fd, struct statfs *buf)
{
	return syscall3(SYS_fstatfs64, fd, sizeof(*buf), (long) buf);
}