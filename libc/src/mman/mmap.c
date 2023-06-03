#include <unistd.h>
#include <sys/mman.h>

#include "../x86/__syscall.h"

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	return (void *) syscall6(SYS_mmap, (long) addr, length, prot, flags, fd, offset);
}