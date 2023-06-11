#include <net/sk_buff.h>
#include <net/sock.h>
#include <mm/mm.h>

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

	/* set socket buffer */
	skb->count = 1;
	skb->data_skb = NULL;
	skb->prev = NULL;
	skb->next = NULL;
	skb->list = NULL;
	skb->sk = NULL;
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
static void __skb_freemem(struct sk_buff_t *skb)
{
	/* update reference count */
	skb->count--;

	/* free socket buffer */
	if (!skb->count)
		kfree(skb->head);
}

/*
 * Free memory of a socket buffer.
 */
static void skb_freemem(struct sk_buff_t *skb)
{
	void *addr = skb->head;

	/* update reference count */
	skb->count--;

	/* free socket buffer */
	if (!skb->count) {
		/* free the skb that contains the actual data if we've clone */
		if (skb->data_skb) {
			addr = skb;
			__skb_freemem(skb->data_skb);
		}

		kfree(addr);
	}
}

/*
 * Free a socket buffer.
 */
void skb_free(struct sk_buff_t *skb, int rw)
{
	struct sock_t *sk;

	/* check socket buffer */
	if (!skb)
		return;

	/* update sock */
	if (skb->sk) {
		sk = skb->sk;

		/* update allocated memory */
		if (rw == FREE_READ) {
			sk->rmem_alloc -= skb->truesize;
		} else {
			if (!sk->dead)
				sk->write_space(sk);
			
			sk->wmem_alloc -= skb->truesize;
		}
	}

	/* free memory */
	skb_freemem(skb);
}