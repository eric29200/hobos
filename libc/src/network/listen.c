
#include <sys/socket.h>
#include <unistd.h>

#include "../x86/__syscall.h"

int listen(int sockfd, int backlog)
{
	return syscall2(SYS_listen, sockfd, backlog);
}