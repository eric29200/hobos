#include <sys/syscall.h>
#include <stderr.h>

/*
 * Uname system call.
 */
int sys_uname(struct utsname_t *buf)
{
	if (!buf)
		return -EINVAL;

	strncpy(buf->sysname, "hobos", UTSNAME_LEN);
	strncpy(buf->nodename, "hobos", UTSNAME_LEN);
	strncpy(buf->release, "0.0.1", UTSNAME_LEN);
	strncpy(buf->version, "hobos 0.0.1", UTSNAME_LEN);
	strncpy(buf->machine, "x86", UTSNAME_LEN);

	return 0;
}
