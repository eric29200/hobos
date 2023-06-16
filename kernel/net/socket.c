#include <proc/sched.h>
#include <fs/fs.h>
#include <fcntl.h>
#include <stdio.h>
#include <stderr.h>

#define MAX_SOCK_ADDR				128

/* socket file operations */
static struct file_operations_t socket_fops;

/*
 * Lookup for a socket.
 */
static struct socket_t *sockfd_lookup(int sockfd, struct file_t **filpp, int *err)
{
	struct inode_t *inode;
	struct file_t *filp;

	/* check file descriptor */
	if (sockfd < 0 || sockfd >= NR_OPEN || !current_task->files->filp[sockfd]) {
		*err = -EBADF;
		return NULL;
	}

	/* get inode */
	filp = current_task->files->filp[sockfd];
	inode = filp->f_inode;
	if (!inode || !inode->i_sock) {
		*err = -ENOTSOCK;
		return NULL;
	}

	/* set output file */
	if (filpp)
		*filpp = filp;

	return &inode->u.socket_i;
}

/*
 * Get a file descriptor.
 */
static int get_fd(struct inode_t *inode)
{
	struct file_t *filp;
	int fd;

	/* get an empty file */
	filp = get_empty_filp();
	if (!filp)
		return -1;

	/* find a free solet */
	for (fd = 0; fd < NR_OPEN; fd++)
		if (!current_task->files->filp[fd])
			break;

	/* no free slot */
	if (fd >= NR_OPEN) {
		filp->f_ref = 0;
		return -1;
	}

	/* set file */
	current_task->files->filp[fd] = filp;
	FD_CLR(fd, &current_task->files->close_on_exec);
	filp->f_op = &socket_fops;
	filp->f_mode = 3;
	filp->f_flags = O_RDWR;
	filp->f_ref = 1;
	filp->f_pos = 0;
	filp->f_inode = inode;

	/* update inode */
	if (inode) 
		inode->i_ref++;

	return(fd);
}

/*
 * Allocate a socket.
 */
static struct socket_t *sock_alloc()
{
	struct inode_t *inode;
	struct socket_t *sock;

	/* get an empty inode */
	inode = get_empty_inode(NULL);
	if (!inode)
		return NULL;

	/* set inode */
	inode->i_mode = S_IFSOCK;
	inode->i_sock = 1;
	inode->i_uid = current_task->uid;
	inode->i_gid = current_task->gid;

	/* set socket */
	sock = &inode->u.socket_i;
	memset(sock, 0, sizeof(struct socket_t));
	sock->state = SS_UNCONNECTED;
	sock->inode = inode;

	return sock;
}

/*
 * Release a peer socket.
 */
static void sock_release_peer(struct socket_t *peer)
{
	peer->state = SS_DISCONNECTING;
	task_wakeup_all(&peer->wait);
}

/*
 * Release a socket.
 */
static void sock_release(struct socket_t *sock)
{
	struct socket_t *peer, *next;
	socket_state_t old_state;

	/* mark socket "disconnecting" */
	old_state = sock->state;
	if (old_state != SS_UNCONNECTED)
		sock->state = SS_DISCONNECTING;

	/* wake up anyone waiting for connections */
	for (peer = sock->iconn; peer != NULL; peer = next) {
		next = peer->next;
		sock_release_peer(peer);
	}

	/* wake up anyone we're connected to */
	peer = old_state == SS_CONNECTED ? sock->conn : NULL;
	if (sock->ops)
		sock->ops->release(sock, peer);
	if (peer)
		sock_release_peer(peer);

	/* release inode */
	sock->filp = NULL;
	iput(sock->inode);
}


/*
 * Close a socket.
 */
static int sock_close(struct file_t *filp)
{
	sock_release(&filp->f_inode->u.socket_i);
	return 0;
}

/*
 * Socket read.
 */
static int sock_read(struct file_t *filp, char *buf, int len)
{
	struct socket_t *sock;
	struct msghdr_t msg;
	struct iovec_t iov;

	/* get socket */
	sock = &filp->f_inode->u.socket_i;
	if (sock->flags & SO_ACCEPTCON)
		return -EINVAL;

	/* check length */
	if (len < 0)
		return -EINVAL;
	if (len == 0)
		return 0;

	/* build message */
	memset(&msg, 0, sizeof(struct msghdr_t));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = buf;
	iov.iov_len = len;

	return sock->ops->recvmsg(sock, &msg, len, filp->f_flags & O_NONBLOCK, 0, &msg.msg_namelen);
}

/*
 * Socket write.
 */
static int sock_write(struct file_t *filp, const char *buf, int len)
{
	struct socket_t *sock;
	struct msghdr_t msg;
	struct iovec_t iov;

	/* get socket */
	sock = &filp->f_inode->u.socket_i;
	if (sock->flags & SO_ACCEPTCON)
		return -EINVAL;

	/* check length */
	if (len < 0)
		return -EINVAL;
	if (len == 0)
		return 0;

	/* build message */
	memset(&msg, 0, sizeof(struct msghdr_t));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return sock->ops->sendmsg(sock, &msg, len, filp->f_flags & O_NONBLOCK, 0);
}

/*
 * Seek a socket.
 */
static int sock_lseek(struct file_t *filp, off_t offset, int whence)
{
	UNUSED(filp);
	UNUSED(offset);
	UNUSED(whence);
	return -ESPIPE;
}

/*
 * Socket system call.
 */
int do_socket(int domain, int type, int protocol)
{
	struct socket_t *sock;
	int err, sockfd;

	/* check type */
	if (type != SOCK_STREAM && type != SOCK_DGRAM && type != SOCK_RAW)
		return -EINVAL;
	if (protocol < 0)
		return -EINVAL;

	/* allocate a new socket */
	sock = sock_alloc();
	if (!sock)
		return -ENOSR;

	/* set socket */
	sock->type = type;

	/* create socket */
	switch (domain) {
		case AF_UNIX:
			err = unix_create(sock, protocol);
			break;
		default:
			err = -EINVAL;
			break;
	}

	/* handle error */
	if (err)
		goto err_release;

	/* get socket file descriptor */
	sockfd = get_fd(sock->inode);
	if (sockfd < 0) {
		err = -EINVAL;
		goto err_release;
	}

	/* set file pointer */
	sock->filp = current_task->files->filp[sockfd];

	return sockfd;
err_release:
	sock_release(sock);
	return err;
}

/*
 * Bind system call.
 */
int do_bind(int sockfd, const struct sockaddr *addr, size_t addrlen)
{
	struct socket_t *sock;
	int err;

	/* get socket */
	sock = sockfd_lookup(sockfd, NULL, &err);
	if (!sock)
		return err;

	return sock->ops->bind(sock, addr, addrlen);
}

/*
 * Connect system call.
 */
int do_connect(int sockfd, const struct sockaddr *addr, size_t addrlen)
{
	struct socket_t *sock;
	struct file_t *filp;
	int err;

	/* get socket */
	sock = sockfd_lookup(sockfd, &filp, &err);
	if (!sock)
		return err;

	/* check state */
	switch (sock->state) {
		case SS_UNCONNECTED:
		case SS_CONNECTING:
			break;
		case SS_CONNECTED:
			if (sock->type == SOCK_DGRAM)
				break;
			return -EISCONN;
		default:
			return -EINVAL;
	}

	return sock->ops->connect(sock, addr, addrlen, filp->f_flags);
}

/*
 * Listen system call.
 */
int do_listen(int sockfd, int backlog)
{
	struct socket_t *sock;
	int err;

	/* get socket */
	sock = sockfd_lookup(sockfd, NULL, &err);
	if (!sock)
		return err;

	/* check socket state */
	if (sock->state != SS_UNCONNECTED)
		return -EINVAL;

	/* listen not supported */
	if (!sock->ops || !sock->ops->listen)
		return -EOPNOTSUPP;

	/* protocol listen */
	err = sock->ops->listen(sock, backlog);
	if (err == 0)
		sock->flags |= SO_ACCEPTCON;

	return err;
}

/*
 * Accept system call.
 */
int do_accept(int sockfd, struct sockaddr *addr, size_t *addrlen)
{
	struct socket_t *sock, *new_sock;
	struct file_t *filp;
	int err, fd;

	/* get socket */
	sock = sockfd_lookup(sockfd, &filp, &err);
	if (!sock)
		return err;
	
	/* check socket state */
	if (sock->state != SS_UNCONNECTED)
		return -EINVAL;
	if (!(sock->flags & SO_ACCEPTCON))
		return -EINVAL;

	/* allocate a new socket */
	new_sock = sock_alloc();
	if (!new_sock)
		return -ENOSR;

	/* set socket operations */
	new_sock->type = sock->type;
	new_sock->ops = sock->ops;

	/* duplicate socket */
	err = sock->ops->dup(new_sock, sock);
	if (err < 0)
		goto err_release;

	/* protocol accept */
	err = new_sock->ops->accept(sock, new_sock, filp->f_flags);
	if (err < 0)
		goto err_release;

	/* get file descriptor */
	fd = err = get_fd(new_sock->inode);
	if (err < 0)
		goto err_release;

	/* set socket file */
	sock->filp = current_task->files->filp[fd];

	/* set address */
	if (addr)
		new_sock->ops->getname(new_sock, addr, addrlen, 1);

	return fd;
err_release:
	sock_release(new_sock);
	return err;
}

/*
 * Send to system call.
 */
int do_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, size_t addrlen)
{
	struct socket_t *sock;
	struct msghdr_t msg;
	struct file_t *filp;
	struct iovec_t iov;
	int err;

	/* get socket */
	sock = sockfd_lookup(sockfd, &filp, &err);
	if (!sock)
		return err;

	/* create message */
	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	msg.msg_name = (struct sockaddr *) dest_addr;
	msg.msg_namelen = addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return sock->ops->sendmsg(sock, &msg, len, filp->f_flags & O_NONBLOCK, flags);
}

/*
 * Receive from system call.
 */
int do_recvfrom(int sockfd, const void *buf, size_t len, int flags, struct sockaddr *src_addr, size_t *addrlen)
{
	struct socket_t *sock;
	struct msghdr_t msg;
	struct file_t *filp;
	struct iovec_t iov;
	int err;

	/* get socket */
	sock = sockfd_lookup(sockfd, &filp, &err);
	if (!sock)
		return err;

	/* create message */
	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	msg.msg_name = (struct sockaddr *) src_addr;
	msg.msg_namelen = MAX_SOCK_ADDR;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	return sock->ops->recvmsg(sock, &msg, len, filp->f_flags & O_NONBLOCK, flags, addrlen);
}

/*
 * Socket file operations.
 */
static struct file_operations_t socket_fops = {
	.close			= sock_close,
	.read			= sock_read,
	.write			= sock_write,
	.lseek			= sock_lseek,
};