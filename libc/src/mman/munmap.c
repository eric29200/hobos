#include <unistd.h>
#include <sys/mman.h>

#include "../x86/__syscall.h"

int munmap(void *addr, size_t length)
{
	return syscall2(SYS_munmap, (long) addr, length);
}