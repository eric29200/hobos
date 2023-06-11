
#include <sys/socket.h>
#include <unistd.h>

#include "../x86/__syscall.h"

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	return syscall3(SYS_bind, sockfd, (long) addr, addrlen);
}