#include <sys/socket.h>
#include <unistd.h>

#include "../x86/__syscall.h"

int socket(int domain, int type, int protocol)
{
	return syscall3(SYS_socket, domain, type, protocol);
}