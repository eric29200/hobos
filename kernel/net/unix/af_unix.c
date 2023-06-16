#include <net/socket.h>
#include <net/sock.h>
#include <net/unix/un.h>
#include <net/inet/tcp.h>
#include <proc/sched.h>
#include <mm/mm.h>
#include <fs/fs.h>
#include <fcntl.h>
#include <stderr.h>

/* UNIX sockets list */
static unix_socket_t *unix_socket_list = NULL;

/*
 * Make name = end name with '\0'.
 */
static void unix_mkname(struct sockaddr_un *sunaddr, size_t len)
{
	if (len >= sizeof(struct sockaddr_un))
		len = sizeof(struct sockaddr_un) - 1;

	((char *) sunaddr)[len] = 0;
}

/*
 * Insert a UNIX socket.
 */
static void unix_insert_socket(unix_socket_t *sk)
{
	sk->next = unix_socket_list;
	unix_socket_list = sk;
}

/*
 * Remove a UNIX socket.
 */
static void unix_remove_socket(unix_socket_t *sk)
{
	unix_socket_t **s;

	for (s = &unix_socket_list; *s != NULL;) {
		if (*s == sk) {
			*s = sk->next;
			return;
		}

		s = &((*s)->next);
	}
}

/*
 * Find a UNIX socket.
 */
static unix_socket_t *unix_find_socket(struct inode_t *inode)
{
	unix_socket_t *sk;

	for (sk = unix_socket_list; sk != NULL; sk = sk->next)
		if (sk->protinfo.af_unix.inode == inode)
			return sk;

	return NULL;
}

/*
 * Find a UNIX socket.
 */
static unix_socket_t *unix_find_other(const char *pathname, int *err)
{
	struct inode_t *inode;
	unix_socket_t *sk;
	int ret;

	/* get inode */
	ret = open_namei(AT_FDCWD, NULL, pathname, O_RDWR, S_IFSOCK, &inode);
	if (ret) {
		*err = ret;
		return NULL;
	}

	/* get UNIX socket */
	sk = unix_find_socket(inode);
	if (!sk) {
		iput(inode);
		*err = -ECONNREFUSED;
		return NULL;
	}

	iput(inode);
	return sk;
}

/*
 * Destroy a UNIX socket.
 */
static void unix_destroy_socket(unix_socket_t *sk)
{
	struct sk_buff_t *skb;
	unix_socket_t *osk;

	/* remove socket from list */
	unix_remove_socket(sk);

	/* free all incoming messages */
	for (;;) {
		/* next message */
		skb = skb_dequeue(&sk->receive_queue);
		if (!skb)
			break;

		/* listening socket : close end point */
		if (sk->state == TCP_LISTEN) {
			osk = skb->sk;
			osk->state = TCP_CLOSE;
			skb_free(skb, FREE_WRITE);
			osk->state_change(osk);
		} else {
			skb_free(skb, FREE_WRITE);
		}
	}

	/* release inode */
	if (sk->protinfo.af_unix.inode) {
		iput(sk->protinfo.af_unix.inode);
		sk->protinfo.af_unix.inode = NULL;
	}

	/* decrement locks */
	sk->protinfo.af_unix.locks--;

	/* free socket */
	if (sk->protinfo.af_unix.locks == 0) {
		if (sk->protinfo.af_unix.name)
			kfree(sk->protinfo.af_unix.name);

		sk_free(sk);
	}
}

/*
 * Wait for data.
 */
static void unix_data_wait(unix_socket_t *sk)
{
	if (!skb_peek(&sk->receive_queue)) {
		sk->socket->flags |= SO_WAITDATA;
		task_sleep(sk->sleep);
		sk->socket->flags &= ~SO_WAITDATA;
	}
}

/*
 * State change callback.
 */
static void unix_state_change_cb(struct sock_t *sk)
{
	if (!sk->dead)
		task_wakeup_all(sk->sleep);
}

/*
 * Data ready callback.
 */
static void unix_data_ready_cb(struct sock_t *sk, size_t len)
{
	UNUSED(len);

	if (!sk->dead)
		task_wakeup_all(sk->sleep);
}

/*
 * Write space callback.
 */
static void unix_write_space_cb(struct sock_t *sk)
{
	if (!sk->dead)
		task_wakeup_all(sk->sleep);
}

/*
 * Duplicate a socket.
 */
static int unix_dup(struct socket_t *new_sock, struct socket_t *old_sock)
{
	UNUSED(old_sock);
	return unix_create(new_sock, 0);
}

/*
 * Release a UNIX socket.
 */
static int unix_release(struct socket_t *sock, struct socket_t *peer)
{
	unix_socket_t *sk_pair, *sk = sock->data;

	/* unused peer */
	UNUSED(peer);

	/* check socket */
	if (!sk)
		return 0;

	/* mark socket dead */
	sk->state_change(sk);
	sk->dead = 1;

	/* alarm pair socket */
	sk_pair = (unix_socket_t *) sk->protinfo.af_unix.other;
	if (sk->type == SOCK_STREAM && sk_pair && sk_pair->state != TCP_LISTEN) {
		sk_pair->shutdown = SHUTDOWN_MASK;
		sk_pair->state_change(sk_pair);
	}

	/* decrement pair socket locks */
	if (sk_pair)
		sk_pair->protinfo.af_unix.locks--;

	/* destroy socket */
	sk->protinfo.af_unix.other = NULL;
	unix_destroy_socket(sk);

	return 0;
}
 
 /*
  * Get socket name.
  */
static int unix_getname(struct socket_t *sock, struct sockaddr *addr, size_t *addrlen, int peer)
{
	struct sockaddr_un *sunaddr = (struct sockaddr_un *) addr;
	unix_socket_t *sk = sock->data;

	/* get peer name */	
	if (peer) {
		if (!sk->protinfo.af_unix.other)
			return -ENOTCONN;
		sk = sk->protinfo.af_unix.other;
	}

	/* set family */
	sunaddr->sun_family = AF_UNIX;

	/* not bound */
	if (!sk->protinfo.af_unix.name) {
		*sunaddr->sun_path = 0;
		*addrlen = sizeof(sunaddr->sun_family) + 1;
		return 0;
	}

	*addrlen = sizeof(sunaddr->sun_family) + strlen(sk->protinfo.af_unix.name) + 1;
	strcpy(sunaddr->sun_path, sk->protinfo.af_unix.name);
	return 0;
}

/*
 * Bind a UNIX socket.
 */
static int unix_bind(struct socket_t *sock, const struct sockaddr *addr, size_t addrlen)
{
	struct sockaddr_un *sunaddr = (struct sockaddr_un *) addr;
	unix_socket_t *sk = sock->data;
	int ret;

	/* already bound */
	if (sk->protinfo.af_unix.name)
		return -EINVAL;

	/* check input address */
	if (addrlen > sizeof(struct sockaddr_un) || addrlen < 3 || sunaddr->sun_family != AF_UNIX)
		return -EINVAL;

	/* fix path name */
	unix_mkname(sunaddr, addrlen);

	/* already bound */
	if (sk->protinfo.af_unix.inode)
		return -EINVAL;

	/* allocate sock name */
	sk->protinfo.af_unix.name = kmalloc(addrlen + 1);
	if (!sk->protinfo.af_unix.name)
		return -EINVAL;

	/* set sock name */
	memcpy(sk->protinfo.af_unix.name, sunaddr->sun_path, addrlen + 1);

	/* create socket and try to open it */
	ret = do_mknod(AT_FDCWD, sk->protinfo.af_unix.name, S_IFSOCK | S_IRWXUGO, 0);
	if (ret == 0)
		ret = open_namei(AT_FDCWD, NULL, sk->protinfo.af_unix.name, O_RDWR, S_IFSOCK, &sk->protinfo.af_unix.inode);

	/* free address on error */
	if (ret < 0) {
		kfree(sk->protinfo.af_unix.name);
		sk->protinfo.af_unix.name = NULL;
		return ret == -EEXIST ? -EADDRINUSE : ret;
	}

	return 0;
}

/*
 * Initiate a connection on a UNIX socket.
 */
static int unix_connect(struct socket_t *sock, const struct sockaddr *addr, size_t addrlen, int flags)
{
	struct sockaddr_un *sunaddr = (struct sockaddr_un *) addr;
	unix_socket_t *other, *sk = sock->data;
	struct sk_buff_t *skb;
	int err;

	/* SOCK_STREAM : check socket state */
	if (sk->type == SOCK_STREAM && sk->protinfo.af_unix.other) {
		if (sock->state == SS_CONNECTING && sk->state == TCP_ESTABLISHED) {
			sock->state = SS_CONNECTED;
			return 0;
		}

		if (sock->state == SS_CONNECTING && sk->state == TCP_CLOSE) {
			sock->state = SS_UNCONNECTED;
			return -ECONNREFUSED;
		}

		if (sock->state != SS_CONNECTING)
			return -EISCONN;

		if (flags & O_NONBLOCK)
			return -EALREADY;
	}

	/* check input address */
	if (addrlen < 3 || sunaddr->sun_family != AF_UNIX)
		return -EINVAL;

	/* fix path name */
	unix_mkname(sunaddr, addrlen);

	/* Datagram socket */
	if (sk->type == SOCK_DGRAM) {
		/* disconnect if needed */
		if (sk->protinfo.af_unix.other) {
			sk->protinfo.af_unix.other->protinfo.af_unix.locks--;
			sk->protinfo.af_unix.other = NULL;
			sock->state = SS_UNCONNECTED;
		}

		/* find other socket */
		other = unix_find_other(sunaddr->sun_path, &err);
		if (!other)
			return err;

		if (other->type != sk->type)
			return -EPROTOTYPE;

		/* connected */
		other->protinfo.af_unix.locks++;
		sk->protinfo.af_unix.other = other;
		sock->state = SS_CONNECTED;
		sk->state = TCP_ESTABLISHED;
		return 0;
	}

	/* unconnected socket : send a SYN message */
	if (sock->state == SS_UNCONNECTED) {
		/* allocate a socket buffer */
		skb = sock_alloc_send_skb(sk, 0, 0, &err);
		if (!skb)
			return err;

		/* set socket buffer */
		skb->sk = sk;
		sk->state = TCP_CLOSE;

		/* find other socket */
		unix_mkname(sunaddr, addrlen);
		other = unix_find_other(sunaddr->sun_path, &err);
		if (!other) {
			skb_free(skb, FREE_WRITE);
			return err;
		}

		/* wrong end point */
		if (other->type != sk->type) {
			skb_free(skb, FREE_WRITE);
			return -EPROTOTYPE;
		}

		/* queue message in other socket */
		other->protinfo.af_unix.locks++;
		other->ack_backlog++;
		sk->protinfo.af_unix.other = other;
		skb_queue_tail(&other->receive_queue, skb);

		/* update socket state */
		sk->state = TCP_SYN_SENT;
		sock->state = SS_CONNECTING;

		/* wake up other socket */
		other->data_ready(other, 0);
	}
			
	/* wait for an accept */
	while (sk->state == TCP_SYN_SENT) {
		if (flags & O_NONBLOCK)
			return -EINPROGRESS;

		task_sleep(sk->sleep);

		if (signal_pending(current_task))
			return -ERESTARTSYS;
	}
	
	/* check connection */
	if (sk->state == TCP_CLOSE) {
		sk->protinfo.af_unix.other->protinfo.af_unix.locks--;
		sk->protinfo.af_unix.other = NULL;
		sock->state = SS_UNCONNECTED;
		return -ECONNREFUSED;
	}
	
	/* done */
	sock->state = SS_CONNECTED;
	return 0;
}

/*
 * Listen on a UNIX socket.
 */
static int unix_listen(struct socket_t *sock, int backlog)
{
	unix_socket_t *sk = sock->data;

	/* check socket type */
	if (sk->type != SOCK_STREAM)
		return -EOPNOTSUPP;

	/* unbounded socket */
	if (!sk->protinfo.af_unix.name)
		return -EINVAL;

	sk->max_ack_backlog = backlog;
	sk->state = TCP_LISTEN;
	return 0;
}

/*
 * Accept a UNIX connection.
 */
static int unix_accept(struct socket_t *sock, struct socket_t *new_sock, int flags)
{
	unix_socket_t *tsk, *sk = sock->data, *new_sk = new_sock->data;
	struct sk_buff_t *skb;

	/* check socket */
	if (sk->type != SOCK_STREAM)
		return -EOPNOTSUPP;
	if (sk->state != TCP_LISTEN)
		return -EINVAL;

	/* copy pathname */
	if (sk->protinfo.af_unix.name) {
		new_sk->protinfo.af_unix.name = kmalloc(strlen(sk->protinfo.af_unix.name) + 1);
		if (!new_sk->protinfo.af_unix.name)
			return -ENOMEM;
		strcpy(new_sk->protinfo.af_unix.name, sk->protinfo.af_unix.name);
	}

	/* wait for a message */
	for (;;) {
		skb = skb_dequeue(&sk->receive_queue);
		if (skb)
			break;

		if (flags & O_NONBLOCK)
			return -EAGAIN;
		
		task_sleep(sk->sleep);

		if (signal_pending(current_task))
			return -ERESTARTSYS;
	}

	/* free socket buffer (just used as a tag) */
	tsk = skb->sk;
	skb_free(skb, FREE_WRITE);

	/* connection established */
	sk->ack_backlog--;
	new_sk->protinfo.af_unix.other = tsk;
	tsk->protinfo.af_unix.other = new_sk;
	tsk->state = TCP_ESTABLISHED;
	new_sk->state = TCP_ESTABLISHED;

	/* update locks */
	new_sk->protinfo.af_unix.locks++;
	sk->protinfo.af_unix.locks--;
	tsk->protinfo.af_unix.locks++;
	tsk->state_change(tsk);

	return 0;
}

/*
 * Send data.
 */
static int unix_sendmsg(struct socket_t *sock, struct msghdr_t *msg, size_t len, int nonblock, int flags)
{
	struct sockaddr_un *sunaddr = msg->msg_name;
	unix_socket_t *other, *sk = sock->data;
	struct sk_buff_t *skb;
	size_t sent, size;
	int err;

	/* check socket error */
	if (sk->err)
		return sock_error(sk);

	/* unsupported flags */
	if (flags & MSG_OOB)
		return -EOPNOTSUPP;
	else if (flags)
		return -EINVAL;

	/* SOCK_STREAM : sunaddr must be NULL */
	if (sunaddr && sock->type == SOCK_STREAM) {
		if (sk->state == TCP_ESTABLISHED)
			return -EISCONN;
		return -EOPNOTSUPP;
	}

	/* check end point */
	if (!sunaddr && !sk->protinfo.af_unix.other)
		return -ENOTCONN;

	/* send data */
	for (sent = 0; sent < len;) {
		size = len - sent;

		/* keep 2 messages in the queue */
		if (size > (sk->sndbuf - sizeof(struct sk_buff_t)) / 2) {
			if (sock->type == SOCK_DGRAM)
				return -EMSGSIZE;

			size = (sk->sndbuf - sizeof(struct sk_buff_t)) / 2;
		}

		/* allocate a socket buffer */
		skb = sock_alloc_send_skb(sk, size, nonblock, &err);
		if (!skb) {
			if (sent) {
				sk->err = err;
				return sent;
			}

			return err;
		}

		/* get socket buffer size */
		size = skb_tailroom(skb);

		/* set socket buffer */
		skb->sk = sk;

		/* copy message to socket buffer */
		memcpy_fromiovec(skb_put(skb, size), msg->msg_iov, size);

		/* find end point */
		if (!sunaddr) {
			other = sk->protinfo.af_unix.other;

			if (sock->type == SOCK_DGRAM && other->dead) {
				other->protinfo.af_unix.locks--;
				sk->protinfo.af_unix.other = NULL;
				sock->state = SS_UNCONNECTED;
				skb_free(skb, FREE_WRITE);
				return sent ? (int) sent : -ECONNRESET;
			}
		} else {
			unix_mkname(sunaddr, msg->msg_namelen);
			other = unix_find_other(sunaddr->sun_path, &err);
			if (!other) {
				skb_free(skb, FREE_WRITE);
				return sent ? (int) sent : err;
			}
		}

		/* queue message */
		skb_queue_tail(&other->receive_queue, skb);

		/* alarm other socket */
		other->data_ready(other, size);

		/* update sent size */
		sent += size;
	}

	return sent;
}

/*
 * Receive data.
 */
static int unix_recvmsg(struct socket_t *sock, struct msghdr_t *msg, size_t len, int nonblock, int flags, size_t *addrlen)
{
	struct sockaddr_un *sunaddr = msg->msg_name;
	size_t ct, n, done, iov_len, copied = 0;
	struct iovec_t *iov = msg->msg_iov;
	unix_socket_t *sk = sock->data;
	struct sk_buff_t *skb;
	void *buf;

	/* check socket error */
	if (sk->err)
		return sock_error(sk);

	/* unsupported flags */
	if (flags & MSG_OOB)
		return -EOPNOTSUPP;
	else if (flags)
		return -EINVAL;

	/* reset address length */
	if (*addrlen)
		*addrlen = 0;
	
	/* receive each message */
	for (ct = msg->msg_iovlen; ct != 0; ct--) {
		/* next iov */
		buf = iov->iov_base;
		iov_len = iov->iov_len;
		iov++;
		done = 0;

		while (done < iov_len) {
			/* done */
			if (copied && (flags & MSG_PEEK))
				return copied;
			if (copied == len)
				return copied;

			/* dequeue next message */
			skb = skb_dequeue(&sk->receive_queue);

			/* no message available : wait for data */
			if (!skb) {
				if (sk->shutdown & RCV_SHUTDOWN)
					return copied;
				if (copied)
					return copied;
				if (nonblock)
					return -EAGAIN;
				if (signal_pending(current_task))
					return -ERESTARTSYS;

				unix_data_wait(sk);
				continue;
			}

			/* set address */
			if (msg->msg_name) {
				sunaddr->sun_family = AF_UNIX;
				if (skb->sk->protinfo.af_unix.name) {
					memcpy(sunaddr->sun_path, skb->sk->protinfo.af_unix.name, UNIX_PATH_MAX);
					if (addrlen)
						*addrlen = strlen(sunaddr->sun_path);
				}

				if (addrlen)
					*addrlen += sizeof(short);
			}

			/* copy data to buffer */
			n = skb->len <= iov_len - done ? skb->len : iov_len - done;
			memcpy(buf, skb->data, n);

			/* update counts */
			copied += n;
			done += n;
			buf += n;

			/* pull data from socket buffer */
			if (!(flags & MSG_PEEK))
				skb_pull(skb, n);

			/* remaining data in socket buffer : queue it */
			if (skb->len) {
				skb_queue_head(&sk->receive_queue, skb);
				continue;
			}

			/* free socket buffer */
			skb_free(skb, FREE_WRITE);

			/* SOCK_DGRAM : don't wait for full buffer */
			if (sock->type == SOCK_DGRAM)
				return copied;
		}
	}

	return copied;
}

/*
 * Unix protocol operations.
 */
static struct proto_ops_t unix_ops = {
	.family			= AF_UNIX,
	.dup			= unix_dup,
	.release		= unix_release,
	.getname		= unix_getname,
	.bind			= unix_bind,
	.connect		= unix_connect,
	.listen			= unix_listen,
	.accept			= unix_accept,
	.sendmsg		= unix_sendmsg,
	.recvmsg		= unix_recvmsg,
};

/*
 * Create a UNIX socket.
 */
int unix_create(struct socket_t *sock, int protocol)
{
	unix_socket_t *sk;

	/* check protocol */
	if (protocol && protocol != PF_UNIX)
		return -EPROTONOSUPPORT;

	/* check socket type */
	switch(sock->type) {
		case SOCK_STREAM:
			sock->ops = &unix_ops;
			break;
		case SOCK_DGRAM:
			sock->ops = &unix_ops;
			break;
		case SOCK_RAW:
			sock->type = SOCK_DGRAM;
			sock->ops = &unix_ops;
			break;
		default:
			return -ESOCKTNOSUPPORT;
	}

	/* allocate UNIX socket */
	sk = (unix_socket_t *) sk_alloc();
	if (!sk)
		return -ENOMEM;

	/* set socket */
	sk->type = sock->type;
	skb_queue_head_init(&sk->write_queue);
	skb_queue_head_init(&sk->receive_queue);
	sk->protinfo.af_unix.family = AF_UNIX;
	sk->protinfo.af_unix.inode = NULL;
	sk->protinfo.af_unix.locks = 1;
	sk->rcvbuf = SK_RMEM_MAX;
	sk->sndbuf = SK_WMEM_MAX;
	sk->state = TCP_CLOSE;
	sk->state_change = unix_state_change_cb;
	sk->data_ready = unix_data_ready_cb;
	sk->write_space = unix_write_space_cb;
	sk->socket = sock;
	sock->data = (void *) sk;
	sk->sleep = &sock->wait;
	unix_insert_socket(sk);

	return 0;
}