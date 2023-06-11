
#include <sys/socket.h>
#include <unistd.h>

#include "../x86/__syscall.h"

int sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
	return syscall6(SYS_sendto, sockfd, (long) buf, len, flags, (long) dest_addr, addrlen);
}