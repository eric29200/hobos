
#include <sys/socket.h>
#include <unistd.h>

int recv(int sockfd, void *buf, size_t len, int flags)
{
	return recvfrom(sockfd, buf, len, flags, NULL, NULL);
}