#ifndef _SK_BUFF_H_
#define _SK_BUFF_H_

#include <stddef.h>
#include <uio.h>

#define FREE_READ			1
#define FREE_WRITE			0

#define SK_WMEM_MAX			65535
#define SK_RMEM_MAX			65535

/*
 * Socket buffer.
 */
struct sk_buff_t {
	struct sk_buff_t *		next;			/* next buffer in list */
	struct sk_buff_t *		prev;			/* previous buffer in list */
	struct sk_buff_head_t *		list;			/* list we are on */
	union {							/* transport layer header */
		uint8_t *		raw;
	} h;
	char				cb[48];			/* private parameters */
	size_t				users;			/* users count */
	int				datarefp;		/* reference count */
	char				is_clone;		/* we are clone */
	char				cloned;			/* may be cloned */
	struct sock_t *			sk;		 	/* socket we are owned by */
	size_t				truesize;		/* buffer size */
	uint8_t *			data;			/* data of the buffer */
	uint8_t *			head;			/* head of the buffer */
	uint8_t *			tail;			/* tail of the buffer */
	uint8_t *			end;			/* end of the buffer */
	size_t				len;			/* socket buffer length */

	void (*destructor)(struct sk_buff_t *);			/* destructor */
};

/*
 * Socket buffer list.
 */
struct sk_buff_head_t {
	struct sk_buff_t *		next;			/* next buffer */
	struct sk_buff_t *		prev;			/* previous buffer */
	size_t				len;			/* buffer list length */
};

/*
 * Get tail room.
 */
static inline size_t skb_tailroom(struct sk_buff_t *skb)
{
	return skb->end - skb->tail;
}

/*
 * Put data into a socket buffer.
 */
static inline uint8_t *skb_put(struct sk_buff_t *skb, size_t len)
{
	uint8_t *ret = skb->tail;
	skb->tail += len;
	skb->len += len;
	return ret;
}

/*
 * Pull data from a socket buffer.
 */
static inline uint8_t *skb_pull(struct sk_buff_t *skb, size_t len)
{
	if (len > skb->len)
		return NULL;

	skb->data += len;
	skb->len -= len;
	return skb->data;
}

/*
 * Init a socket buffer list.
 */
static inline void skb_queue_head_init(struct sk_buff_head_t *list)
{
	list->prev = (struct sk_buff_t *) list;
	list->next = (struct sk_buff_t *) list;
	list->len = 0;
}

/*
 * Is a socket buffer list empty ?
 */
static inline int skb_queue_empty(struct sk_buff_head_t *list)
{
	return (list->next == (struct sk_buff_t *) list);
}

/*
 * Get length of a socket buffer list.
 */
static inline size_t skb_queue_len(struct sk_buff_head_t *list)
{
	return list->len;
}

/*
 * Insert a socket buffer at the beginning of a list.
 */
static inline void skb_queue_head(struct sk_buff_head_t *list, struct sk_buff_t *skb)
{
	struct sk_buff_t *prev, *next;

	/* update list */
	skb->list = list;
	list->len++;

	/* queue skb */
	prev = (struct sk_buff_t *) list;
	next = prev->next;
	skb->next = next;
	skb->prev = prev;
	next->prev = skb;
	prev->next = skb;
}

/*
 * Insert a socket buffer at the end of a list.
 */
static inline void skb_queue_tail(struct sk_buff_head_t *list, struct sk_buff_t *skb)
{
	struct sk_buff_t *prev, *next;

	/* update list */
	skb->list = list;
	list->len++;

	/* queue skb */
	next = (struct sk_buff_t *) list;
	prev = next->prev;
	skb->next = next;
	skb->prev = prev;
	next->prev = skb;
	prev->next = skb;
}

/*
 * Remove a socket buffer from a list.
 */
static inline struct sk_buff_t *skb_dequeue(struct sk_buff_head_t *list)
{
	struct sk_buff_t *l = (struct sk_buff_t *) list;
	struct sk_buff_t *ret;

	/* get next socket buffer */
	ret = list->next;

	/* empty list */
	if (ret == l)
		return NULL;

	/* remove socket buffer from list */
	ret->next->prev = l;
	l->next = ret->next;
	ret->next = NULL;
	ret->prev = NULL;
	list->len--;
	ret->list = NULL;

	return ret;
}

/*
 * Peek a socket buffer from a list.
 */
static inline struct sk_buff_t *skb_peek(struct sk_buff_head_t *list)
{
	struct sk_buff_t *l = ((struct sk_buff_t *) list)->next;
	
	if (l == (struct sk_buff_t *) list)
		l = NULL;

	return l;
}

struct sk_buff_t *skb_alloc(size_t size);
void skb_free(struct sk_buff_t *skb);
int skb_copy_datagram_iovec(struct sk_buff_t *skb, size_t offset, struct iovec_t *to, size_t size);
struct sk_buff_t *skb_recv_datagram(struct sock_t *sk, int flags, int nonblock, int *err);

#endif