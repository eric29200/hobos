#ifndef _UN_H_
#define _UN_H_

#include <net/sock.h>

#define UNIX_PATH_MAX		108

typedef struct sock_t unix_socket_t;				/* unix socket = generic sock */

/*
 * UNIX socket address.
 */
struct sockaddr_un {
	unsigned short	sun_family;				/* AF_UNIX */
	char		sun_path[UNIX_PATH_MAX];		/* pathname */
};

#endif
