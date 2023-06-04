#ifndef _LIBC_STATFS_H_
#define _LIBC_STATFS_H_

#include <sys/types.h>

typedef struct __fsid_t {
	int	__val[2];
} fsid_t;

struct statfs {
	unsigned long		f_type;
	unsigned long		f_bsize;
	fsblkcnt_t		f_blocks;
	fsblkcnt_t		f_bfree;
	fsblkcnt_t		f_bavail;
	fsblkcnt_t		f_files;
	fsblkcnt_t		f_free;
	fsid_t 			f_fsid;
	unsigned long		f_namelen;
	unsigned long		f_frsize;
	unsigned long		f_flags;
	unsigned long		f_spare[4];
};

int statfs(const char *path, struct statfs *buf);
int fstatfs(int fd, struct statfs *buf);

#endif
