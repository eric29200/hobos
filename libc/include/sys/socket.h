#ifndef _LIBC_SOCKET_H_
#define _LIBC_SOCKET_H_

#include <sys/types.h>

#define PF_UNSPEC		0
#define PF_LOCAL		1
#define PF_UNIX			PF_LOCAL
#define PF_FILE			PF_LOCAL
#define PF_INET			2

#define AF_UNSPEC		PF_UNSPEC
#define AF_LOCAL		PF_LOCAL
#define AF_UNIX			AF_LOCAL
#define AF_FILE			AF_LOCAL
#define AF_INET			PF_INET

#define SOCK_STREAM		1
#define SOCK_DGRAM		2

struct sockaddr {
	sa_family_t		sa_family;
	char			sa_data[14];
};

int socket(int domain, int type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int send(int sockfd, const void *buf, size_t len, int flags);
int sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
int recv(int sockfd, void *buf, size_t len, int flags);
int recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

#endif