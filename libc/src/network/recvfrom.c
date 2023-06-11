#include <sys/socket.h>
#include <unistd.h>

#include "../x86/__syscall.h"

int recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	return syscall6(SYS_recvfrom, sockfd, (long) buf, len, flags, (long) src_addr, (long) addrlen);
}