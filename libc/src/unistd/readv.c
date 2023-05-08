#include <sys/uio.h>
#include <unistd.h>

#include "../x86/__syscall.h"

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
	return __syscall_ret(__syscall3(SYS_readv, fd, (long) iov, iovcnt));
}