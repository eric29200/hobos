#ifndef _SOCKET_H_
#define _SOCKET_H_

#include <stddef.h>
#include <uio.h>

/* addresses families */
#define AF_UNIX		 	1
#define AF_INET			2

/* protocol families */
#define PF_UNIX			1
#define PF_INET			2

/* socket types */
#define SOCK_STREAM		1
#define SOCK_DGRAM		2
#define SOCK_RAW		3

/* flags for send/recv */
#define MSG_OOB			1
#define MSG_PEEK		2

/* flags for shutdown */
#define RCV_SHUTDOWN		1
#define SEND_SHUTDOWN		2
#define SHUTDOWN_MASK		3

/* socket options */
#define SOL_SOCKET		1
#define SO_DEBUG		1
#define SO_REUSEADDR		2
#define SO_TYPE			3
#define SO_ERROR		4
#define SO_DONTROUTE		5
#define SO_BROADCAST		6
#define SO_SNDBUF		7
#define SO_RCVBUF		8
#define SO_SNDBUFFORCE		32
#define SO_RCVBUFFORCE		33
#define SO_KEEPALIVE		9
#define SO_OOBINLINE		10
#define SO_NO_CHECK		11
#define SO_PRIORITY		12
#define SO_LINGER		13
#define SO_BSDCOMPAT		14
#define SO_PASSCRED		16
#define SO_PEERCRED		17
#define SO_RCVLOWAT		18
#define SO_SNDLOWAT		19
#define SO_RCVTIMEO		20
#define SO_SNDTIMEO		21
#define SO_ACCEPTCON		(1 << 16)
#define SO_WAITDATA		(1 << 17)
#define SO_NOSPACE		(1 << 18)

/*
 * Socket address.
 */
struct sockaddr {
	uint16_t		sa_family;
	char			sa_data[14];
};

/*
 * Socket state.
 */
typedef enum {
	SS_FREE = 0,
	SS_UNCONNECTED,
	SS_CONNECTING,
	SS_CONNECTED,
	SS_DISCONNECTING,
} socket_state_t;

/*
 * Socket structure.
 */
struct socket_t {
	uint16_t			type;			/* type = STREAM, DGRAM... */
	socket_state_t			state;			/* state = FREE, CONNECTED... */
	long				flags;			/* flags */
	struct wait_queue_t *		wait;			/* wait queue */
	struct inode_t *		inode;			/* associated inode */
	struct file_t *			filp;			/* associated file */
	void *				data;			/* protocol data */
	struct proto_ops_t *		ops;			/* protocol operations */
	struct socket_t *		conn;			/* server socket connected to */
	struct socket_t *		iconn;			/* incomplete client connections */
	struct socket_t *		next;			/* next socket */
};

/*
 * Message.
 */
struct msghdr_t {
	void *				msg_name;		/* socket name */
	size_t				msg_namelen;		/* socket name length */
	struct iovec_t *		msg_iov;		/* data */
	size_t				msg_iovlen;		/* data length */
};

/*
 * Protocol operations.
 */
struct proto_ops_t {
	int			family;
	int (*dup)(struct socket_t *, struct socket_t *);
	int (*release)(struct socket_t *, struct socket_t *);
	int (*getname)(struct socket_t *, struct sockaddr *, size_t *, int);
	int (*bind)(struct socket_t *, const struct sockaddr *, size_t);
	int (*connect)(struct socket_t *, const struct sockaddr *, size_t, int);
	int (*listen)(struct socket_t *, int);
	int (*accept)(struct socket_t *, struct socket_t *, int);
	int (*sendmsg)(struct socket_t *, struct msghdr_t *, size_t, int, int);
	int (*recvmsg)(struct socket_t *, struct msghdr_t *, size_t, int, int, size_t *);
};

/* protocol creation */
int unix_create(struct socket_t *sock, int protocol);

/* iovec operations */
void memcpy_toiovec(struct iovec_t *iov, void *buf, size_t len);
void memcpy_fromiovec(void *buf, struct iovec_t *iov, size_t len);

/* socket system calls */
int do_socket(int domain, int type, int protocol);
int do_bind(int sockfd, const struct sockaddr *addr, size_t addrlen);
int do_connect(int sockfd, const struct sockaddr *addr, size_t addrlen);
int do_listen(int sockfd, int backlog);
int do_accept(int sockfd, struct sockaddr *addr, size_t *addrlen);
int do_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, size_t addrlen);
int do_recvfrom(int sockfd, const void *buf, size_t len, int flags, struct sockaddr *src_addr, size_t *addrlen);

#endif
