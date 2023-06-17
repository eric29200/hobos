#include <net/socket.h>
#include <net/sock.h>
#include <net/unix/un.h>
#include <net/inet/tcp.h>
#include <proc/sched.h>
#include <mm/mm.h>
#include <fs/fs.h>
#include <fcntl.h>
#include <stderr.h>

#define unix_peer(sk)		((sk)->pair)

#define UNIX_DELETE_DELAY	(1 * HZ)
#define UNIX_DESTROY_DELAY	(10 * HZ)

#define UNIX_MAX_DGRAM_QLEN	10

/* prototypes */
static int unix_release_sock(unix_socket_t *sk);
static struct sock_t *unix_create1(struct socket_t *sock);

/* UNIX sockets list */
static unix_socket_t *unix_socket_list = NULL;

/* wait queues */
struct wait_queue_t *unix_ack_wqueue = NULL;
struct wait_queue_t *unix_dgram_wqueue = NULL;

/*
 * Lock a UNIX socket.
 */
static void unix_lock(unix_socket_t *sk)
{
	sk->sock_readers++;
}

/*
 * Unlock a UNIX socket.
 */
static void unix_unlock(unix_socket_t *sk)
{
	sk->sock_readers--;
}

/*
 * Is a UNOX socket locked ?
 */
static int unix_locked(unix_socket_t *sk)
{
	return sk->sock_readers != 0;
}

/*
 * Release a UNIX address.
 */
static void unix_release_addr(struct unix_address_t *addr)
{
	if (addr && --addr->refcnt == 0)
		kfree(addr);
}

/*
 * Destruct a UNIX address.
 */
static void unix_destruct_addr(struct sock_t *sk)
{
	unix_release_addr(sk->protinfo.af_unix.addr);
}

/*
 * Are 2 sockets connected ?
 */
static int unix_our_peer(unix_socket_t *sk, unix_socket_t *osk)
{
	return unix_peer(osk) == sk;
}

/*
 * Is a socket writable ?
 */
static int unix_may_send(unix_socket_t *sk, unix_socket_t *osk)
{
	return (unix_peer(osk) == NULL || unix_our_peer(sk, osk));
}

/*
 * Sleep until data has arrive.
 */
static void unix_data_wait(unix_socket_t * sk)
{
	if (!skb_peek(&sk->receive_queue)) {
		sk->socket->flags |= SO_WAITDATA;
		task_sleep(sk->sleep);
		sk->socket->flags &= ~SO_WAITDATA;
	}
}

/*
 * Make name = end name with '\0'.
 */
static int unix_mkname(struct sockaddr_un *sunaddr, size_t len)
{
	/* check input address */
	if (len <= sizeof(short) || len > sizeof(struct sockaddr_un))
		return -EINVAL;
	if (!sunaddr || sunaddr->sun_family != AF_UNIX)
		return -EINVAL;

	/* abstract address */
	if (!sunaddr->sun_path[0])
		return len;

	/* end address */
	((char *) sunaddr)[len] = 0;
	return strlen(sunaddr->sun_path) + 1 + sizeof(short);
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
 * Find a UNIX socket by its inode.
 */
static unix_socket_t *unix_find_socket_by_inode(struct inode_t *inode)
{
	unix_socket_t *sk;

	for (sk = unix_socket_list; sk != NULL; sk = sk->next) {
		if (sk->protinfo.af_unix.inode == inode) {
			unix_lock(sk);
			return sk;
		}
	}

	return NULL;
}

/*
 * Find a UNIX socket by its name.
 */
static unix_socket_t *unix_find_socket_by_name(struct sockaddr_un *sunaddr, size_t len, int type)
{
	struct unix_address_t *addr;
	unix_socket_t *sk;

	for (sk = unix_socket_list; sk != NULL; sk = sk->next) {
		addr = sk->protinfo.af_unix.addr;

		if (addr->len == len && memcmp(addr->name, sunaddr, len) == 0 && sk->type == type) {
			unix_lock(sk);
			return sk;
		}
	}

	return NULL;
}

/*
 * Find a UNIX socket.
 */
static unix_socket_t *unix_find_other(struct sockaddr_un *sunaddr, size_t len, int type, int *err)
{
	struct inode_t *inode;
	unix_socket_t *sk;
	int ret;

	/* abstract socket */
	if (!sunaddr->sun_path[0]) {
		sk = unix_find_socket_by_name(sunaddr, len, type);
		if (!sk)
			*err = -ECONNREFUSED;

		return sk;
	}

	/* get inode */
	ret = open_namei(AT_FDCWD, NULL, sunaddr->sun_path, O_RDWR, S_IFSOCK, &inode);
	if (ret) {
		*err = ret;
		return NULL;
	}

	/* get UNIX socket */
	sk = unix_find_socket_by_inode(inode);
	if (!sk) {
		iput(inode);
		*err = -ECONNREFUSED;
		return NULL;
	}

	/* release inode */
	iput(inode);

	/* check socket type */
	if (sk->type != type) {
		*err = -EPROTOTYPE;
		return NULL;
	}

	return sk;
}

/*
 * Try to destroy a UNIX socket.
 */
static void unix_destroy_timer(void *arg)
{
	unix_socket_t *sk = (unix_socket_t *) arg;

	/* free socket if not used anymore */
	if (!unix_locked(sk) && sk->wmem_alloc == 0) {
		sk_free(sk);
		return;
	}

	/* retry 10 seconds later */
	sk->timer.expires = jiffies + UNIX_DESTROY_DELAY;
	timer_event_add(&sk->timer);
}

/*
 * Delay a UNIX socket deletion (try after 10 seconds);
 */
static void unix_delayed_delete(unix_socket_t *sk)
{
	timer_event_init(&sk->timer, unix_destroy_timer, sk, jiffies + UNIX_DELETE_DELAY);
	timer_event_add(&sk->timer);
}

/*
 * Destroy a UNIX socket.
 */
static void unix_destroy_socket(unix_socket_t *sk)
{
	struct sk_buff_t *skb;

	/* remove socket */
	unix_remove_socket(sk);

	/* free received buffers */
	for (;;) {
		/* get next buffer */
		skb = skb_dequeue(&sk->receive_queue);
		if (!skb)
			break;

		if (sk->state == TCP_LISTEN)
			unix_release_sock(skb->sk);

		/* free buffer */		
		skb_free(skb);
	}

	/* release inode */
	if (sk->protinfo.af_unix.inode) {
		iput(sk->protinfo.af_unix.inode);
		sk->protinfo.af_unix.inode = NULL;
	}
	
	/* unlocked socket, with no writing buffers remaining : free it immediately */
	if (!unix_locked(sk) && sk->wmem_alloc == 0) {
		sk_free(sk);
		return;
	}
	
	/* else delay delete */
	sk->state = TCP_CLOSE;
	sk->dead = 1;
	unix_delayed_delete(sk);
}

/*
 * Release a UNIX socket.
 */
static int unix_release_sock(unix_socket_t *sk)
{
	unix_socket_t *skpair;

	/* set socket dead */
	sk->state_change(sk);
	sk->dead = 1;
	sk->socket = NULL;

	/* wake up waiting processes */
	if (sk->state == TCP_LISTEN)
		task_wakeup(&unix_ack_wqueue);
	if (sk->state == SOCK_DGRAM)
		task_wakeup(&unix_dgram_wqueue);

	/* handle pair socket */
	skpair = unix_peer(sk);
	if (skpair) {
		/* shutdown pair */
		if (sk->type == SOCK_STREAM && unix_our_peer(sk, skpair)) {
			skpair->data_ready(skpair, 0);
			skpair->shutdown = SHUTDOWN_MASK;
		}

		/* unlock pair */
		unix_unlock(skpair);
	}

	/* destroy socket */
	unix_destroy_socket(sk);

	return 0;
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
	unix_socket_t *sk = sock->sk;

	/* unused peer */
	UNUSED(peer);

	/* check socket */
	if (!sk)
		return 0;

	/* update socket state */
	sock->sk = NULL;
	if (sock->state != SS_UNCONNECTED)
		sock->state = SS_DISCONNECTING;

	return unix_release_sock(sk);
}
 
 /*
  * Get socket name.
  */
static int unix_getname(struct socket_t *sock, struct sockaddr *addr, size_t *addrlen, int peer)
{
	struct sockaddr_un *sunaddr = (struct sockaddr_un *) addr;
	unix_socket_t *sk = sock->sk;

	/* get peer name */	
	if (peer) {
		if (!unix_peer(sk))
			return -ENOTCONN;
		sk = unix_peer(sk);
	}

	/* not bound */
	if (!sk->protinfo.af_unix.addr) {
		sunaddr->sun_family = AF_UNIX;
		*sunaddr->sun_path = 0;
		*addrlen = sizeof(short);
		return 0;
	}

	*addrlen = sk->protinfo.af_unix.addr->len;
	memcpy(sunaddr, sk->protinfo.af_unix.addr->name, *addrlen);
	return 0;
}

/*
 * Bind a UNIX socket.
 */
static int unix_bind(struct socket_t *sock, const struct sockaddr *addr, size_t addrlen)
{
	struct sockaddr_un *sunaddr = (struct sockaddr_un *) addr;
	unix_socket_t *osk, *sk = sock->sk;
	struct unix_address_t *unix_addr;
	struct inode_t *inode;
	int err;

	/* already bound */
	if (sk->protinfo.af_unix.addr || sk->protinfo.af_unix.inode || sunaddr->sun_family != AF_UNIX)
		return -EINVAL;

	/* fix path name */
	err = unix_mkname(sunaddr, addrlen);
	if (err < 0)
		return err;
	else
		addrlen = err;

	/* allocate UNIX address */
	unix_addr = (struct unix_address_t *) kmalloc(sizeof(struct unix_address_t) + addrlen);
	if (!unix_addr)
		return -ENOMEM;
	
	/* set UNIX address */
	memcpy(unix_addr->name, sunaddr, addrlen);
	unix_addr->len = addrlen;
	unix_addr->refcnt = 1;

	/* abstract socket */
	if (!sunaddr->sun_path[0]) {
		/* address already used */
		osk = unix_find_socket_by_name(sunaddr, addrlen, sk->type);
		if (osk) {
			unix_unlock(osk);
			unix_release_addr(unix_addr);
			return -EADDRINUSE;
		}

		/* bound */
		sk->protinfo.af_unix.addr = unix_addr;
		return 0;
	}

	/* create socket node */
	err = do_mknod(AT_FDCWD, sunaddr->sun_path, S_IFSOCK | S_IRWXUGO, 0);
	if (err == 0)
		err = open_namei(AT_FDCWD, NULL, sunaddr->sun_path, 0, S_IFSOCK, &inode);

	/* release address on error */
	if (err) {
		unix_release_addr(unix_addr);
		return err == -EEXIST ? -EADDRINUSE : err;
	}
	
	/* bound */
	sk->protinfo.af_unix.addr = unix_addr;
	sk->protinfo.af_unix.inode = inode;

	return 0;
}

/*
 * Initiate a connection on a UNIX datagram socket.
 */
static int unix_dgram_connect(struct socket_t *sock, const struct sockaddr *addr, size_t addrlen, int flags)
{
	struct sockaddr_un *sunaddr = (struct sockaddr_un *) addr;
	struct sock_t *other, *sk = sock->sk;
	int err;

	/* unused flags */
	UNUSED(flags);

	/* make name */
	err = unix_mkname(sunaddr, addrlen);
	if (err < 0)
		return err;
	else
		addrlen = err;

	/* find destination socket */
	other = unix_find_other(sunaddr, addrlen, sock->type, &err);
	if (!other)
		return err;

	/* check if destination is writable */
	if (!unix_may_send(sk, other)) {
		unix_unlock(other);
		return -EINVAL;
	}

	/* if it was connected, disconnect */
	if (unix_peer(sk)) {
		unix_unlock(unix_peer(sk));
		unix_peer(sk) = NULL;
	}

	/* connect */
	unix_peer(sk) = other;

	return 0;
}

/*
 * Initiate a connection on a UNIX stream socket.
 */
static int unix_stream_connect(struct socket_t *sock, const struct sockaddr *addr, size_t addrlen, int flags)
{
	struct sockaddr_un *sunaddr = (struct sockaddr_un *) addr;
	struct sock_t *newsk = NULL, *sk = sock->sk;
	struct sk_buff_t *skb = NULL;
	unix_socket_t *other = NULL;
	int err;

	/* make name */
	err = unix_mkname(sunaddr, addrlen);
	if (err < 0)
		return err;
	else
		addrlen = err;

restart:
	/* find listening sock */
	other = unix_find_other(sunaddr, addrlen, sk->type, &err);
	if (!other)
		return -ECONNREFUSED;

	/* wait for connection */
	while (other->ack_backlog >= other->max_ack_backlog) {
		/* unlock other socket while waiting */
		unix_unlock(other);

		/* handle dead socket */
		if (other->dead || other->state != TCP_LISTEN)
			return -ECONNREFUSED;

		/* non blocking */
		if (flags & O_NONBLOCK)
			return -EAGAIN;
		
		/* sleep */
		task_sleep(&unix_ack_wqueue);

		/* handle signals */
		if (signal_pending(current_task))
			return -ERESTARTSYS;

		/* retry */
		goto restart;
        }

	/* create new sock for complete connection */
	newsk = unix_create1(NULL);
	if (!newsk) {
		err = -ENOMEM;
		goto out;
	}

	/* allocate skb for sending to listening sock */
	skb = sock_wmalloc(newsk, 1);
	if (!skb) {
		err = -ENOMEM;
		goto out;
	}

	/* check socket state */
	if (sock->state != SS_UNCONNECTED) {
		err = sock->state == SS_CONNECTED ? -EISCONN : -EINVAL;
		goto out;
	}

	/* check socket state */
	if (sk->state != TCP_CLOSE) {
		err = -EINVAL;
		goto out;
	}

	/* check listener state */
	if (other->dead || other->state != TCP_LISTEN) {
		err = -ECONNREFUSED;
		goto out;
	}

	/* send a SYN message */
	UNIXCB(skb).attr = MSG_SYN;

	/* set up connecting socket */
	sock->state = SS_CONNECTED;
	unix_peer(sk) = newsk;
	unix_lock(sk);
	sk->state = TCP_ESTABLISHED;

	/* set up newly created sock */
	unix_peer(newsk) = sk;
	unix_lock(newsk);
	newsk->state = TCP_ESTABLISHED;
	newsk->type = SOCK_STREAM;

	/* copy address information from listening to new sock */
	if (other->protinfo.af_unix.addr)
	{
		other->protinfo.af_unix.addr->refcnt++;
		newsk->protinfo.af_unix.addr = other->protinfo.af_unix.addr;
	}

	/* set inode */
	if (other->protinfo.af_unix.inode) {
		newsk->protinfo.af_unix.inode = other->protinfo.af_unix.inode;
		newsk->protinfo.af_unix.inode->i_ref++;
	}

	/* send info to listening sock */
	other->ack_backlog++;
	skb_queue_tail(&other->receive_queue,skb);
	other->data_ready(other, 0);
	unix_unlock(other);

	return 0;
out:
	if (skb)
		skb_free(skb);
	if (newsk)
		unix_destroy_socket(newsk);
	if (other)
		unix_unlock(other);
	return err;
}

/*
 * UNIX datagram listen.
 */
static int unix_dgram_listen(struct socket_t *sock, int backlog)
{
	UNUSED(sock);
	UNUSED(backlog);
	return -EOPNOTSUPP;
}

/*
 * UNIX stream listen.
 */
static int unix_stream_listen(struct socket_t *sock, int backlog)
{
	struct sock_t *sk = sock->sk;

	/* check socket state */
	if (sock->state != SS_UNCONNECTED) 
		return -EINVAL;
	if (sock->type != SOCK_STREAM)
		return -EOPNOTSUPP;

	/* unbound socket */
	if (!sk->protinfo.af_unix.addr)
		return -EINVAL;
	if (backlog > SOMAXCONN)
		backlog = SOMAXCONN;

	/* update socket state */
	sk->max_ack_backlog = backlog;
	sk->state = TCP_LISTEN;
	sock->flags |= SO_ACCEPTCON;

	return 0;
}

/*
 * UNIX datagram accept.
 */
static int unix_dgram_accept(struct socket_t *sock, struct socket_t *newsock, int flags)
{
	UNUSED(sock);
	UNUSED(newsock);
	UNUSED(flags);
	return -EOPNOTSUPP;
}

/*
 * UNIX stream accept.
 */
static int unix_stream_accept(struct socket_t *sock, struct socket_t *newsock, int flags)
{
	unix_socket_t *tsk, *sk = sock->sk, *newsk = newsock->sk;
	struct sk_buff_t *skb;
	
	/* check socket state */
	if (sock->state != SS_UNCONNECTED)
		return -EINVAL; 
	if (!(sock->flags & SO_ACCEPTCON)) 
		return -EINVAL;
	if (sock->type != SOCK_STREAM)
		return -EOPNOTSUPP;
	if (sk->state != TCP_LISTEN)
		return -EINVAL;
		
	for (;;) {
		/* wait for a message */
		skb = skb_dequeue(&sk->receive_queue);
		if (!skb) {
			/* non blocking */
			if (flags & O_NONBLOCK)
				return -EAGAIN;

			/* sleep */
			task_sleep(sk->sleep);

			/* handle signals */
			if (signal_pending(current_task))
				return -ERESTARTSYS;

			continue;
		}

		/* not a SYN message */
		if (!(UNIXCB(skb).attr & MSG_SYN)) {
			tsk = skb->sk;
			tsk->state_change(tsk);
			skb_free(skb);
			continue;
		}

		/* done : free socket buffer and wake up eventual processes */
		tsk = skb->sk;
		if (sk->max_ack_backlog == sk->ack_backlog--)
			task_wakeup_all(&unix_ack_wqueue);

		skb_free(skb);
		break;
	}


	/* attach accepted sock to socket */
	newsock->state = SS_CONNECTED;
	newsock->sk = tsk;
	tsk->sleep = newsk->sleep;
	tsk->socket = newsock;

	/* destroy handed sock */
	newsk->socket = NULL;
	unix_destroy_socket(newsk);

	return 0;
}

/*
 * Receive a message.
 */
static int unix_dgram_recvmsg(struct socket_t *sock, struct msghdr_t *msg, size_t size, int flags)
{
	struct sock_t *sk = sock->sk;
	struct sk_buff_t *skb;
	int err;

	/* check flags */
	if (flags & MSG_OOB)
		return -EOPNOTSUPP;

	/* reset source address */
	msg->msg_namelen = 0;

	/* dequeue/peek a socket buffer */
	skb = skb_recv_datagram(sk, flags, flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	/* wake up eventual tasks */
	task_wakeup_all(&unix_dgram_wqueue);

	/* set source address */
	if (msg->msg_name) {
		msg->msg_namelen = sizeof(short);

		if (skb->sk->protinfo.af_unix.addr) {
			msg->msg_namelen = skb->sk->protinfo.af_unix.addr->len;
			memcpy(msg->msg_name, skb->sk->protinfo.af_unix.addr->name, skb->sk->protinfo.af_unix.addr->len);
		}
	}

	/* check size */
	if (size > skb->len)
		size = skb->len;
	else if (size < skb->len)
		msg->msg_flags |= MSG_TRUNC;

	/* get skb data */
	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, size);

	/* free socket buffer */
	skb_free(skb);

	return err ? err : (int) size;
}

/*
 * Receive a message.
 */
static int unix_stream_recvmsg(struct socket_t *sock, struct msghdr_t *msg, size_t len, int flags)
{
	struct sockaddr_un *sunaddr = msg->msg_name;
	size_t chunk, copied = 0, target = 1;
	struct sock_t *sk = sock->sk;
	struct sk_buff_t *skb;
	int err;

	/* check flags */
	if (sock->flags & SO_ACCEPTCON) 
		return -EINVAL;
	if (flags & MSG_OOB)
		return -EOPNOTSUPP;
	if (flags & MSG_WAITALL)
		target = len;
		
	/* reset source address */
	msg->msg_namelen = 0;

	/* read */
	while (len) {
		/* wait for a message */
		skb = skb_dequeue(&sk->receive_queue);
		if (!skb) {
			/* end */
			if (copied >= target)
				break;

			/* handle error */
			if (sk->err)
				return sock_error(sk);

			/* handle shutdown */
			if (sk->shutdown & RCV_SHUTDOWN)
				break;

			/* non blocking */
			if (flags & MSG_DONTWAIT)
				return -EAGAIN;

			/* sleep */
			unix_data_wait(sk);
		
			/* handle signals */
			if (signal_pending(current_task))
				return -ERESTARTSYS;

			continue;
		}

		/* copy address */
		if (sunaddr) {
			msg->msg_namelen = sizeof(short);
			if (skb->sk->protinfo.af_unix.addr) {
				msg->msg_namelen = skb->sk->protinfo.af_unix.addr->len;
				memcpy(sunaddr, skb->sk->protinfo.af_unix.addr->name, skb->sk->protinfo.af_unix.addr->len);
			}

			/* copy address just once */
			sunaddr = NULL;
		}

		/* choose size to receive */
		chunk = skb->len <= len ? skb->len : len;

		/* copy skb data to message */
		err = memcpy_toiovec(msg->msg_iov, skb->data, chunk);
		if (err) {
			skb_queue_head(&sk->receive_queue, skb);
			return copied ? (int) copied : -EFAULT;
		}

		/* update sizes */
		copied += chunk;
		len -= chunk;

		/* put message back and return */
		if (flags & MSG_PEEK) {
			skb_queue_head(&sk->receive_queue, skb);
			break;
		}

		/* mark read part of skb as used */
		skb_pull(skb, chunk);

		/* put the skb back if we didn't use it up */
		if (skb->len) {
			skb_queue_head(&sk->receive_queue, skb);
			break;
		}

		/* else free skb */
		skb_free(skb);
	}

	return copied;
}

/*
 * Send a message.
 */
static int unix_dgram_sendmsg(struct socket_t *sock, struct msghdr_t *msg, size_t size)
{
	struct sockaddr_un *sunaddr = msg->msg_name;
	struct sock_t *sk = sock->sk;
	struct sk_buff_t *skb;
	unix_socket_t *other;
	int err, namelen = 0;

	/* check flags */
	if (msg->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;
	if (msg->msg_flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL))
		return -EINVAL;

	/* get destination address */
	if (msg->msg_namelen) {
		namelen = unix_mkname(sunaddr, msg->msg_namelen);
		if (namelen < 0)
			return namelen;
	} else {
		sunaddr = NULL;
		if (!unix_peer(sk))
			return -ENOTCONN;
	}

	/* check message size */
	if (size > sk->sndbuf)
		return -EMSGSIZE;

	/* allocate a socket buffer */
	skb = sock_alloc_send_skb(sk, size, msg->msg_flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	/* copy message to socket buffer */
	skb->h.raw = skb->data;
	err = memcpy_fromiovec(skb_put(skb, size), msg->msg_iov, size);
	if (err)
		goto err_free;

	/* pair socket is dead : reset connection */
	other = unix_peer(sk);
	if (other && other->dead)
	{
dead:
		unix_unlock(other);
		unix_peer(sk) = NULL;
		other = NULL;
		err = -ECONNRESET;

		/* if sunaddr != NULL, try to send unconnected message */
		if (!sunaddr)
			goto err_free;
	}

	/* get destination socket */
	if (!other) {
		if (!sunaddr) {
			err = -ECONNRESET;
			goto err_free;
		}

		/* find destination */
		other = unix_find_other(sunaddr, namelen, sk->type, &err);
		if (!other)
			goto err_free;

		/* check if destination is writable */
		if (!unix_may_send(sk, other)) {
			err = -EINVAL;
			goto err_unlock;
		}
	}

	/* sleep while other receive queue is full */
	while (skb_queue_len(&other->receive_queue) >= UNIX_MAX_DGRAM_QLEN) {
		/* non blocking */
		if (msg->msg_flags & MSG_DONTWAIT) {
			err = -EAGAIN;
			goto err_unlock;
		}

		/* sleep */
		task_sleep(&unix_dgram_wqueue);

		/* handle dead socket */
		if (other->dead)
			goto dead;
		
		/* handle shutdown */
		if (sk->shutdown & SEND_SHUTDOWN) {
			err = -EPIPE;
			goto err_unlock;
		}

		/* handle signals */
		if (signal_pending(current_task))
		{
			err = -ERESTARTSYS;
			goto err_unlock;
		}
	}

	/* queue socket buffer in destination socket */
	skb_queue_tail(&other->receive_queue, skb);
	other->data_ready(other, size);
	
	/* unlock other socket if not connected */
	if (!unix_peer(sk))
		unix_unlock(other);

	return size;
err_unlock:
	unix_unlock(other);
err_free:
	skb_free(skb);
	return err;
}

/*
 * Send a message.
 */
static int unix_stream_sendmsg(struct socket_t *sock, struct msghdr_t *msg, size_t len)
{
	struct sock_t *sk = sock->sk;
	struct sk_buff_t *skb;
	unix_socket_t *other;
	int err;

	/* check flags */
	if (sock->flags & SO_ACCEPTCON) 
		return -EINVAL;
	if (msg->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;
	if (msg->msg_flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL))
		return -EINVAL;

	/* destination address should be NULL */
	if (msg->msg_namelen)
		return sk->state == TCP_ESTABLISHED ? -EISCONN : -EOPNOTSUPP;
	
	/* check connection */
	if (!unix_peer(sk))
		return -ENOTCONN;

	/* handle shutdown */
	if (sk->shutdown & SEND_SHUTDOWN) {
		if (!(msg->msg_flags & MSG_NOSIGNAL))
			task_signal(current_task->pid, SIGPIPE);
		return -EPIPE;
	}

	/* create a socket buffer */
	skb = sock_alloc_send_skb(sk, len, msg->msg_flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;
	
	/* copy message to socket buffer */
	err = memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len);
	if (err) {
		skb_free(skb);
		return -EFAULT;
	}

	/* check end point */
	other = unix_peer(sk);
	if (other->dead || (sk->shutdown & SEND_SHUTDOWN)) {
		skb_free(skb);

		if (!(msg->msg_flags & MSG_NOSIGNAL))
			task_signal(current_task->pid, SIGPIPE);
		return -EPIPE;
	}

	/* queue message in other socket */
	skb_queue_tail(&other->receive_queue, skb);
	other->data_ready(other, len);
	
	return len;
}

/*
 * UNIX datagram protocol operations.
 */
static struct proto_ops_t unix_dgram_ops = {
	.family			= AF_UNIX,
	.dup			= unix_dup,
	.release		= unix_release,
	.getname		= unix_getname,
	.bind			= unix_bind,
	.connect		= unix_dgram_connect,
	.listen			= unix_dgram_listen,
	.accept			= unix_dgram_accept,
	.recvmsg		= unix_dgram_recvmsg,
	.sendmsg		= unix_dgram_sendmsg,
};

/*
 * UNIX stream protocol operations.
 */
static struct proto_ops_t unix_stream_ops = {
	.family			= AF_UNIX,
	.dup			= unix_dup,
	.release		= unix_release,
	.getname		= unix_getname,
	.bind			= unix_bind,
	.connect		= unix_stream_connect,
	.listen			= unix_stream_listen,
	.accept			= unix_stream_accept,
	.recvmsg		= unix_stream_recvmsg,
	.sendmsg		= unix_stream_sendmsg,
};

/*
 * Create a UNIX internal socket.
 */
static struct sock_t *unix_create1(struct socket_t *sock)
{
	struct sock_t *sk;

	/* allocate a UNIX socket */
	sk = sk_alloc();
	if (!sk)
		return NULL;

	/* init data */
	sock_init_data(sock, sk);

	/* set UNIX socket */
	sk->destruct = unix_destruct_addr;
	sk->protinfo.af_unix.family = PF_UNIX;
	sk->protinfo.af_unix.inode = NULL;
	
	/* insert UNIX socket */
	unix_insert_socket(sk);

	return sk;
}

/*
 * Create a UNIX socket.
 */
int unix_create(struct socket_t *sock, int protocol)
{
	/* check protocol */
	if (protocol && protocol != PF_UNIX)
		return -EPROTONOSUPPORT;

	/* check socket type */
	switch(sock->type) {
		case SOCK_STREAM:
			sock->ops = &unix_stream_ops;
			break;
		case SOCK_DGRAM:
			sock->ops = &unix_dgram_ops;
			break;
		case SOCK_RAW:
			sock->type = SOCK_DGRAM;
			sock->ops = &unix_dgram_ops;
			break;
		default:
			return -ESOCKTNOSUPPORT;
	}

	/* create internal socket */
	return unix_create1(sock) ? 0 : -ENOMEM;
}