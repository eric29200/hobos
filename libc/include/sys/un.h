#ifndef _LIBC_UN_H_
#define _LIBC_UN_H_

#include <sys/types.h>

struct sockaddr_un {
	sa_family_t	sun_family;
	char		sun_path[108];
};

#endif