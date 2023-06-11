
#include <sys/socket.h>
#include <unistd.h>

int send(int sockfd, const void *buf, size_t len, int flags)
{
	return sendto(sockfd, buf, len, flags, NULL, 0);
}