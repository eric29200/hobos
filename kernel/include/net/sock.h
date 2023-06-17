#ifndef _SOCK_H_
#define _SOCK_H_

#include <net/sk_buff.h>
#include <net/unix/un.h>
#include <proc/timer.h>
#include <fs/fs.h>

/*
 * UNIX address.
 */
struct unix_address_t {
	int				refcnt;			/* reference count */
	size_t				len;			/* address length */
	struct sockaddr_un		name[0];		/* address */
};

/*
 * UNIX socket options.
 */
struct unix_opt_t {
	int				family;			/* family = AF_UNIX */
	struct unix_address_t *		addr;			/* UNIX address */
	struct inode_t *		inode;			/* inode */
	struct sock_t *			other;			/* connected socket */
};

/*
 * Internal socket.
 */
struct sock_t {
	uint16_t			type;			/* sock type */
	uint8_t				state;			/* sock state */
	uint8_t				dead;			/* dead socket */
	uint8_t				shutdown;		/* shutdown socket */
	int				err;			/* sock error */
	int				sock_readers;		/* users count */
	struct timer_event_t		timer;			/* timer to cleanup socket */
	union {
		struct unix_opt_t	af_unix;
	} protinfo;						/* protocol informations */
	struct socket_t *		socket;			/* socket */
	struct wait_queue_t **		sleep;			/* wait queue */
	size_t				rcvbuf;			/* receive buffer size */
	size_t				sndbuf;			/* send buffer size */
	size_t				rmem_alloc;		/* memory allocated for read/receive */
	size_t				wmem_alloc;		/* memory allocated for write/send */
	uint8_t				ack_backlog;		/* number of acks backlog */
	uint8_t				max_ack_backlog;	/* maximum of acks backlog */
	struct sk_buff_head_t 		receive_queue;		/* receive queue */
	struct sk_buff_head_t 		write_queue;		/* write queue */
	struct sock_t *			pair;			/* pair socket */
	struct sock_t *			next;			/* next socket */

	void (*state_change)(struct sock_t *);			/* state change callback */
	void (*data_ready)(struct sock_t *, size_t);		/* data ready callback */
	void (*write_space)(struct sock_t *);			/* write space callback */
	void (*destruct)(struct sock_t *);			/* destruct a socket */
};

/*
 * Get socket error and clear it.
 */
static inline int sock_error(struct sock_t *sk)
{
	int err = sk->err;
	sk->err = 0;
	return err;
}
	
/*
 * Connection based socket ?
 */
static inline int connection_based(struct sock_t *sk)
{
	return sk->type == SOCK_SEQPACKET || sk->type == SOCK_STREAM;
}

struct sock_t *sk_alloc();
void sk_free(struct sock_t *sk);
void sock_init_data(struct socket_t *sock, struct sock_t *sk);
struct sk_buff_t *sock_wmalloc(struct sock_t *sk, size_t size);
struct sk_buff_t *sock_alloc_send_skb(struct sock_t *sk, size_t size, int nonblock, int *err);

#endif
