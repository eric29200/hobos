#include <unistd.h>
#include <sys/statfs.h>

#include "../x86/__syscall.h"

int fstatfs(int fd, struct statfs *buf)
{
	return syscall2(SYS_fstatfs64, fd, (long) buf);
}