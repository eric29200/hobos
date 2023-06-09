#ifndef _LIBC_FCNTL_H_
#define _LIBC_FCNTL_H_

#include <sys/types.h>

#define O_CREAT		0100
#define O_EXCL		0200
#define O_NOCTTY	0400
#define O_TRUNC		01000
#define O_APPEND	02000
#define O_NONBLOCK	04000
#define O_DSYNC		010000
#define O_SYNC		04010000
#define O_RSYNC		04010000
#define O_DIRECTORY	0200000
#define O_NOFOLLOW	0400000
#define O_CLOEXEC	02000000

#define O_ASYNC		020000
#define O_DIRECT	040000
#define O_LARGEFILE	0100000
#define O_NOATIME	01000000
#define O_PATH		010000000
#define O_TMPFILE	020200000
#define O_NDELAY	O_NONBLOCK

#define O_SEARCH   	O_PATH
#define O_EXEC     	O_PATH
#define O_TTY_INIT 	0

#define O_ACCMODE	(03 | O_SEARCH)
#define O_RDONLY 	00
#define O_WRONLY 	01
#define O_RDWR   	02

#define F_OFD_GETLK	36
#define F_OFD_SETLK	37
#define F_OFD_SETLKW	38

#define F_DUPFD_CLOEXEC	1030

#define FD_CLOEXEC	1

#define F_DUPFD		0
#define F_GETFD		1
#define F_SETFD		2
#define F_GETFL		3
#define F_SETFL		4

#define SEEK_SET	0
#define SEEK_CUR	1
#define SEEK_END	2

#define AT_FDCWD 		(-100)
#define AT_SYMLINK_NOFOLLOW 	0x100
#define AT_REMOVEDIR 		0x200
#define AT_SYMLINK_FOLLOW	0x400
#define AT_EACCESS		0x200
#define AT_EMPTY_PATH		0x1000

#define F_OK		0
#define R_OK		4
#define W_OK		2
#define X_OK		1

int fcntl(int fd, int cmd, ...);
int open(const char *pathname, int flags, ...);
int creat(const char *filename, mode_t mode);

#endif
