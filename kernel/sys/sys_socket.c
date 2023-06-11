#include <sys/syscall.h>

/*
 * Socket system call.
 */
int sys_socket(int family, int type, int protocol)
{
	return do_socket(family, type, protocol);
}