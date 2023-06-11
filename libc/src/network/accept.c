#include <sys/socket.h>
#include <unistd.h>

#include "../x86/__syscall.h"

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	return syscall3(SYS_accept, sockfd, (long) addr, (long) addrlen);
}