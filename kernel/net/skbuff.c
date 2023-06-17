#include <net/sk_buff.h>
#include <net/sock.h>
#include <net/inet/tcp.h>
#include <proc/sched.h>
#include <mm/mm.h>
#include <stderr.h>
#include <uio.h>

/*
 * Allocate a socket buffer.
 */
struct sk_buff_t *skb_alloc(size_t size)
{
	struct sk_buff_t *skb;
	size_t len = size;
	uint8_t *buf;

	/* make size multiple of 16 bytes */
	size = (size + 15) & ~15;
	size += sizeof(struct sk_buff_t);
	
	/* allocate buffer (sk_buff + data)*/
	buf = kmalloc(size);
	if (!buf)
		return NULL;
	
	/* set socket buffer (= end of allocated memory) */
	skb = (struct sk_buff_t *) (buf + size) - 1;

	/* memzero socket buffer */
	memset(skb, 0, sizeof(struct sk_buff_t));

	/* set socket buffer */
	skb->users = 1;
	skb->datarefp = 1;
	skb->truesize = size;
	skb->head = buf;
	skb->data = buf;
	skb->tail = buf;
	skb->end = buf + len;
	skb->len = 0;

	return skb;
}

/*
 * Free memory of a socket buffer.
 */
static void skb_freemem(struct sk_buff_t *skb)
{
	/* free memory if no mo more reference */
	if (!skb->cloned || --skb->datarefp == 0)
		kfree(skb->head);
}

/*
 * Free a socket buffer.
 */
void skb_free(struct sk_buff_t *skb)
{
	/* check socket buffer */
	if (!skb)
		return;

	/* free memory if not used anymore */
	if (--skb->users == 0) {
		if (skb->destructor)
			skb->destructor(skb);

		/* free socket buffer */
		skb_freemem(skb);
	}
}

/*
 * Copy a datagram socket buffer to iovec.
 */
int skb_copy_datagram_iovec(struct sk_buff_t *skb, size_t offset, struct iovec_t *to, size_t size)
{
	return memcpy_toiovec(to, skb->h.raw + offset, size);
}
 
/*
 * Receive a datagram buffer;
 */
struct sk_buff_t *skb_recv_datagram(struct sock_t *sk, int flags, int nonblock, int *err)
{
	struct sk_buff_t *skb;
	int error;
	 
	/* check socket error */
	if (sk->err) {
		error = sock_error(sk);
		goto no_packet;
	}

	/* no data */
	while (skb_queue_empty(&sk->receive_queue)) {
		/* check socket error */
		if (sk->err) {
			error = sock_error(sk);
			goto no_packet;
		}

		/* shutdown */
		if (sk->shutdown & RCV_SHUTDOWN)
			goto no_packet;

		/* sequenced packets can come disconnected : report the problem */
		if(connection_based(sk) && sk->state != TCP_ESTABLISHED) {
			error = -ENOTCONN;
			goto no_packet;
		}

		/* handle signals */
		if (signal_pending(current_task)) {
			error = -ERESTARTSYS;
			goto no_packet;
		}

		/* non blocking */
		if (nonblock) {
			error = -EAGAIN;
			goto no_packet;
		}

		/* sleep */
		task_sleep(sk->sleep);
	}

	/* peek a buffer */
	if (flags & MSG_PEEK) {
		skb = skb_peek(&sk->receive_queue);
		skb->users++;
		return skb;
	}

	/* else dequeue a buffer */
	return skb_dequeue(&sk->receive_queue);
no_packet:
	*err = error;
	return NULL;
}