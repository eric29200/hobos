#include <net/socket.h>
#include <string.h>

/*
 * Copy buffer to iov struct.
 */
int memcpy_toiovec(struct iovec_t *iov, void *buf, size_t len)
{
	size_t n;

	while (len > 0) {
		if (iov->iov_len) {
			n = iov->iov_len <= len ? iov->iov_len : len;
			memcpy(iov->iov_base, buf, n);

			buf += n;
			iov->iov_base += n;
			iov->iov_len -= n;
			len -= n;
		}

		iov++;
	}

	return 0;
}

/*
 * Copy iovec struct to buffer.
 */
int memcpy_fromiovec(void *buf, struct iovec_t *iov, size_t len)
{
	size_t n;

	while (len > 0) {
		if (iov->iov_len) {
			n = iov->iov_len <= len ? iov->iov_len : len;
			memcpy(buf, iov->iov_base, n);

			buf += n;
			iov->iov_base += n;
			iov->iov_len -= n;
			len -= n;
		}

		iov++;
	}

	return 0;
}