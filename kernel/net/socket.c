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
static struct socket_t *sockfd_lookup(int sockfd, int *err)
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
	inode->i_mode = S_IFSOCK | S_IRWXUGO;
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
 * Release a socket.
 */
static void sock_release(struct socket_t *sock)
{
	/* mark socket "disconnecting" */
	if (sock->state != SS_UNCONNECTED)
		sock->state = SS_DISCONNECTING;
	
	/* release */
	if (sock->ops)
		sock->ops->release(sock, NULL);

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

	return sock->ops->recvmsg(sock, &msg, len, !(filp->f_flags & O_NONBLOCK) ? 0 : MSG_DONTWAIT);
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

	/* check length */
	if (len < 0)
		return -EINVAL;
	if (len == 0)
		return 0;

	/* build message */
	memset(&msg, 0, sizeof(struct msghdr_t));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = !(filp->f_flags & O_NONBLOCK) ? 0 : MSG_DONTWAIT;
	iov.iov_base = (void *) buf;
	iov.iov_len = len;

	return sock->ops->sendmsg(sock, &msg, len);
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
	sock = sockfd_lookup(sockfd, &err);
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
	int err;

	/* get socket */
	sock = sockfd_lookup(sockfd, &err);
	if (!sock)
		return err;

	return sock->ops->connect(sock, addr, addrlen, sock->filp->f_flags);
}

/*
 * Listen system call.
 */
int do_listen(int sockfd, int backlog)
{
	struct socket_t *sock;
	int err;

	/* get socket */
	sock = sockfd_lookup(sockfd, &err);
	if (!sock)
		return err;

	return sock->ops->listen(sock, backlog);
}

/*
 * Accept system call.
 */
int do_accept(int sockfd, struct sockaddr *addr, size_t *addrlen)
{
	struct socket_t *sock, *new_sock;
	int err, fd;

	/* get socket */
	sock = sockfd_lookup(sockfd, &err);
	if (!sock)
		return err;
	
	/* allocate a new socket */
	new_sock = sock_alloc();
	if (!new_sock)
		return -EMFILE;

	/* set socket operations */
	new_sock->type = sock->type;
	new_sock->ops = sock->ops;

	/* duplicate socket */
	err = sock->ops->dup(new_sock, sock);
	if (err < 0)
		goto err_release;

	/* protocol accept */
	err = new_sock->ops->accept(sock, new_sock, sock->filp->f_flags);
	if (err < 0)
		goto err_release;

	/* get file descriptor */
	err = get_fd(new_sock->inode);
	if (err < 0)
		goto err_release;
	else
		fd = err;

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
	struct iovec_t iov;
	int err;

	/* get socket */
	sock = sockfd_lookup(sockfd, &err);
	if (!sock)
		return err;

	/* set flags */
	if (sock->filp->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;

	/* create message */
	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	msg.msg_name = (struct sockaddr *) dest_addr;
	msg.msg_namelen = addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = flags;

	return sock->ops->sendmsg(sock, &msg, len);
}

/*
 * Receive from system call.
 */
int do_recvfrom(int sockfd, const void *buf, size_t len, int flags, struct sockaddr *src_addr, size_t *addrlen)
{
	char address[MAX_SOCK_ADDR];
	struct socket_t *sock;
	struct msghdr_t msg;
	struct iovec_t iov;
	int err;

	/* get socket */
	sock = sockfd_lookup(sockfd, &err);
	if (!sock)
		return err;

	/* set flags */
	if (sock->filp->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;

	/* create message */
	iov.iov_base = (void *) buf;
	iov.iov_len = len;
	msg.msg_name = address;
	msg.msg_namelen = MAX_SOCK_ADDR;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* receive message */
	err = sock->ops->recvmsg(sock, &msg, len, flags);

	/* set source address */
	if (err >= 0 && src_addr) {
		*addrlen = msg.msg_namelen;
		memcpy(src_addr, address, *addrlen);
	}

	return err;
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