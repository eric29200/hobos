#include <net/sock.h>
#include <proc/sched.h>
#include <stderr.h>

/*
 * Allocate a socket.
 */
struct sock_t *sk_alloc()
{
	struct sock_t *sk;

	/* allocate a new sock */
	sk = (struct sock_t *) kmalloc(sizeof(struct sock_t));
	if (!sk)
		return NULL;

	/* memzero */
	memset(sk, 0, sizeof(struct sock_t));

	return sk;
}

/*
 * Free a socket.
 */
void sk_free(struct sock_t *sk)
{
	if (sk)
		kfree(sk);
}

/*
 * Allocate a write socket buffer.
 */
static struct sk_buff_t *sock_wmalloc(struct sock_t *sk, size_t size)
{
	struct sk_buff_t *skb;

	/* allocate buffer if write memory < send buffer size */
	if (sk) {
		if (sk->wmem_alloc + size < sk->sndbuf) {
			skb = skb_alloc(size);
			if (sk)
				sk->wmem_alloc += skb->truesize;

			return skb;
		}

		return NULL;
	}

	/* orphan skb */
	return skb_alloc(size);
}

/*
 * Allocate a send socket buffer.
 */
struct sk_buff_t *sock_alloc_send_skb(struct sock_t *sk, size_t size, int nonblock, int *err)
{
	struct sk_buff_t *skb;

	for (;;) {
		/* check socket error */
		if (sk->err) {
			*err = sock_error(sk);
			return NULL;
		}

		/* socket shutdown */
		if (sk->shutdown & SEND_SHUTDOWN) {
			*err = -EPIPE;
			return NULL;
		}

		/* try to allocate a socket buffer */
		skb = sock_wmalloc(sk, size);
		if (skb)
			break;

		/* allocation failed */
		sk->socket->flags |= SO_NOSPACE;
		if (nonblock) {
			*err = -EAGAIN;
			return NULL;
		}

		/* wait for free space */
		sk->socket->flags &= ~SO_NOSPACE;
		task_sleep(sk->sleep);

		/* handle signal */
		if (signal_pending(current_task)) {
			*err = -ERESTARTSYS;
			return NULL;
		}
	}

	return skb;
}