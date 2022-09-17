#include <net/unix/un.h>
#include <net/sk_buff.h>
#include <mm/mm.h>
#include <fs/fs.h>
#include <proc/sched.h>
#include <fcntl.h>
#include <stderr.h>
#include <string.h>
#include <uio.h>

/* sockets table */
extern struct socket_t sockets[NR_SOCKETS];

/*
 * Find a UNIX socket.
 */
static struct unix_sock_t *unix_find_socket(struct inode_t *inode)
{
	struct unix_sock_t *sk;
	int i;

	for (i = 0; i < NR_SOCKETS; i++) {
		if (sockets[i].family == AF_UNIX) {
			sk = (struct unix_sock_t *) sockets[i].data;
			if (sk && sk->inode == inode)
				return sk;
		}
	}

	return NULL;
}

/*
 * Find other UNIX socket.
 */
static int unix_find_other(char *pathname, struct unix_sock_t **res)
{
	struct inode_t *inode;
	int ret;

	/* reset result socket -*/
	*res = NULL;

	/* find socket inode */
	ret = open_namei(AT_FDCWD, pathname, S_IFSOCK, 0, &inode);
	if (ret)
		return ret;

	/* find UNIX socket */
	*res = unix_find_socket(inode);
	if (!*res)
		ret = -ECONNREFUSED;

	/* release inode */
	iput(inode);
	return ret;
}

/*
 * Create a socket.
 */
static int unix_create(struct socket_t *sock, int protocol)
{
	struct unix_sock_t *sk;

	/* check protocol */
	if (protocol != 0)
		return -EINVAL;

	/* allocate UNIX socket */
	sock->data = sk = (struct unix_sock_t *) kmalloc(sizeof(struct unix_sock_t));
	if (!sk)
		return -ENOMEM;

	/* set UNIX socket */
	memset(sk, 0, sizeof(struct unix_sock_t));
	sk->protocol = protocol;
	sk->sock = sock;
	sk->other = NULL;
	INIT_LIST_HEAD(&sk->skb_list);

	return 0;
}

/*
 * Duplicate a socket.
 */
static int unix_dup(struct socket_t *sock, struct socket_t *sock_new)
{
	struct unix_sock_t *sk;

	/* get UNIX socket */
	sk = (struct unix_sock_t *) sock->data;
	if (!sk)
		return -EINVAL;

	return unix_create(sock_new, sk->protocol);
}

/*
 * Release a socket.
 */
static int unix_release(struct socket_t *sock)
{
	struct unix_sock_t *sk;

	/* get UNIX socket */
	sk = (struct unix_sock_t *) sock->data;
	if (!sk)
		return 0;

	/* release inode */
	if (sk->inode)
		iput(sk->inode);

	/* release UNIX socket */
	kfree(sock->data);

	return 0;
}

/*
 * Close a socket.
 */
static int unix_close(struct socket_t *sock)
{
	UNUSED(sock);
	return 0;
}

/*
 * Poll on a socket.
 */
static int unix_poll(struct socket_t *sock, struct select_table_t *wait)
{
	struct unix_sock_t *sk;
	int mask = 0;

	/* get inet socket */
	sk = (struct unix_sock_t *) sock->data;
	if (!sk)
		return -EINVAL;

	/* check if there is a message in the queue */
	if (!list_empty(&sk->skb_list))
		mask |= POLLIN;

	/* check if socket can write */
	if (sk->sock->state != SS_DEAD)
		mask |= POLLOUT;

	/* add wait queue to select table */
	select_wait(&sock->wait, wait);

	return mask;
}

/*
 * Receive a message.
 */
static int unix_recvmsg(struct socket_t *sock, struct msghdr_t *msg, int flags)
{
	struct unix_sock_t *sk, *from;
	size_t n, i, len, count = 0;
	struct sk_buff_t *skb;
	void *buf;

	/* unused flags */
	UNUSED(flags);

	/* get UNIX socket */
	sk = (struct unix_sock_t *) sock->data;
	if (!sk)
		return -EINVAL;

	/* sleep until we receive a packet */
	for (;;) {
		/* signal received : restart system call */
		if (!sigisemptyset(&current_task->sigpend))
			return -ERESTARTSYS;

		/* message received : break */
		if (!list_empty(&sk->skb_list))
			break;

		/* sleep */
		task_sleep(&sk->sock->wait);
	}

	/* get first message */
	skb = list_first_entry(&sk->skb_list, struct sk_buff_t, list);

	/* set buffer */
	len = skb->len;
	buf = skb->head;

	/* copy message */
	for (i = 0; i < msg->msg_iovlen; i++) {
		n = len > msg->msg_iov[i].iov_len ? msg->msg_iov[i].iov_len : len;
		memcpy(msg->msg_iov[i].iov_base, buf, n);
		count += n;
	}

	/* set source address */
	if (skb->sock && skb->sock->data) {
		from = (struct unix_sock_t *) skb->sock->data;
		memcpy(msg->msg_name, &from->sunaddr, from->sunaddr_len);
	}

	/* remove and free socket buffer */
	list_del(&skb->list);
	skb_free(skb);

	return count;
}

/*
 * Send a message.
 */
static int unix_sendmsg(struct socket_t *sock, const struct msghdr_t *msg, int flags)
{
	struct sockaddr_un *sunaddr = msg->msg_name;
	struct unix_sock_t *sk, *other;
	struct sk_buff_t *skb;
	size_t len, i;
	void *buf;
	int ret;

	/* unused flags */
	UNUSED(flags);

	/* get UNIX socket */
	sk = (struct unix_sock_t *) sock->data;
	if (!sk)
		return -EINVAL;

	/* find other socket */
	if (sunaddr) {
		ret = unix_find_other(sunaddr->sun_path, &other);
		if (ret)
			return ret;
	} else {
		other = sk->other;
		if (!other)
			return -ENOTCONN;
	}

	/* compute data length */
	len = 0;
	for (i = 0; i < msg->msg_iovlen; i++)
		len += msg->msg_iov[i].iov_len;

	/* allocate a socket buffer */
	skb = skb_alloc(len);
	if (!skb)
		return -ENOMEM;

	/* set socket */
	skb->sock = sock;

	/* copy message */
	buf = skb_put(skb, len);
	for (i = 0; i < msg->msg_iovlen; i++) {
		memcpy(buf, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
		buf += msg->msg_iov[i].iov_len;
	}

	/* queue message to other socket */
	list_add_tail(&skb->list, &other->skb_list);

	/* wake up eventual readers */
	task_wakeup_all(&other->sock->wait);

	return len;
}

/*
 * Bind system call (attach an address to a socket).
 */
static int unix_bind(struct socket_t *sock, const struct sockaddr *addr, size_t addrlen)
{
	struct unix_sock_t *sk;
	int ret;

	/* check address length */
	if (addrlen < UN_PATH_OFFSET || addrlen > sizeof(struct sockaddr_un))
		return -EINVAL;

	/* get UNIX socket */
	sk = (struct unix_sock_t *) sock->data;
	if (!sk)
		return -EINVAL;

	/* socket already bound */
	if (sk->sunaddr_len || sk->inode)
		return -EBUSY;

	/* set socket address */
	memcpy(&sk->sunaddr, addr, addrlen);
	sk->sunaddr.sun_path[addrlen - UN_PATH_OFFSET] = 0;
	sk->sunaddr_len = addrlen;

	/* create socket file */
	ret = do_mknod(AT_FDCWD, sk->sunaddr.sun_path, S_IFSOCK | S_IRWXUGO, 0);
	if (ret)
		return ret;

	/* get inode */
	ret = open_namei(AT_FDCWD, sk->sunaddr.sun_path, 0, S_IFSOCK, &sk->inode);
	if (ret)
		return ret;

	return 0;
}

/*
 * Accept system call.
 */
static int unix_accept(struct socket_t *sock, struct socket_t *sock_new, struct sockaddr *addr)
{
	struct unix_sock_t *sk, *sk_new;
	struct list_head_t *pos;
	struct sk_buff_t *skb;

	/* socket must be listening */
	if (sock->type != SOCK_STREAM || sock->state != SS_LISTENING)
		return -EINVAL;

	/* get UNIX sockets */
	sk = (struct unix_sock_t *) sock->data;
	sk_new = (struct unix_sock_t *) sock_new->data;
	if (!sk || !sk_new)
		return -EINVAL;

	for (;;) {
		/* signal received : restart system call */
		if (!sigisemptyset(&current_task->sigpend))
			return -ERESTARTSYS;

		/* for each received packet */
		list_for_each(pos, &sk->skb_list) {
			/* get socket buffer */
			skb = list_entry(pos, struct sk_buff_t, list);

			/* set new socket */
			sock_new->state = SS_CONNECTED;
			sk_new->other = (struct unix_sock_t *) skb->sock->data;
			((struct unix_sock_t *) skb->sock->data)->other = sk_new;

			/* set destination address */
			memcpy(addr, &sk_new->other->sunaddr, sizeof(struct sockaddr_un));

			/* free socket buffer */
			list_del(&skb->list);
			skb_free(skb);

			return 0;
		}

		/* disconnected : break */
		if (sock->state == SS_DISCONNECTING)
			return 0;

		/* sleep */
		task_sleep(&sock->wait);
	}

	return 0;
}

/*
 * Connect system call.
 */
static int unix_connect(struct socket_t *sock, const struct sockaddr *addr)
{
	struct sockaddr_un *sunaddr = (struct sockaddr_un *) addr;
	struct unix_sock_t *sk, *other;
	struct sk_buff_t *skb;
	int ret;

	/* get UNIX socket */
	sk = (struct unix_sock_t *) sock->data;
	if (!sk)
		return -EINVAL;

	/* find other unix socket */
	ret = unix_find_other(sunaddr->sun_path, &other);
	if (ret)
		return ret;

	/* datagramm socket : just connect */
	if (sock->type == SOCK_DGRAM) {
		sk->other = other;
		sock->state = SS_CONNECTED;
		return 0;
	}

	/* create an empty packet */
	skb = skb_alloc(0);
	if (!skb)
		return -ENOMEM;

	/* queue empty packet */
	skb->sock = sock;
	list_add_tail(&skb->list, &other->skb_list);

	/* wake up eventual reader */
	task_wakeup(&other->sock->wait);

	/* set socket */
	sk->other = other;
	sock->state = SS_CONNECTING;

	return 0;
}

/*
 * Get peer name system call.
 */
static int unix_getpeername(struct socket_t *sock, struct sockaddr *addr, size_t *addrlen)
{
	struct unix_sock_t *sk;

	/* get UNIX socket */
	sk = (struct unix_sock_t *) sock->data;
	if (!sk)
		return -EINVAL;

	/* copy destination address */
	if (sk->other) {
		memset(addr, 0, sizeof(struct sockaddr));
		memcpy(addr, &sk->other->sunaddr, sk->other->sunaddr_len);
		*addrlen = sk->other->sunaddr_len;
	}

	return 0;
}

/*
 * Get sock name system call.
 */
static int unix_getsockname(struct socket_t *sock, struct sockaddr *addr, size_t *addrlen)
{
	struct unix_sock_t *sk;

	/* get UNIX socket */
	sk = (struct unix_sock_t *) sock->data;
	if (!sk)
		return -EINVAL;

	/* copy destination address */
	memset(addr, 0, sizeof(struct sockaddr));
	memcpy(addr, &sk->sunaddr, sk->sunaddr_len);
	*addrlen = sk->sunaddr_len;

	return 0;
}

/*
 * UNIX operations.
 */
struct prot_ops unix_ops = {
	.create		= unix_create,
	.dup		= unix_dup,
	.release	= unix_release,
	.close		= unix_close,
	.poll		= unix_poll,
	.recvmsg	= unix_recvmsg,
	.sendmsg	= unix_sendmsg,
	.bind		= unix_bind,
	.accept		= unix_accept,
	.connect	= unix_connect,
	.getpeername	= unix_getpeername,
	.getsockname	= unix_getsockname,
};
