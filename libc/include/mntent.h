#ifndef _LIBC_MNTENT_H_
#define _LIBC_MNTENT_H_

#include <stdio.h>

struct mntent {
	char *	mnt_fsname;
	char *	mnt_dir;
	char *	mnt_type;
	char *	mnt_ops;
	int	mnt_freq;
	int	mnt_passno;
};

struct mntent *getmntent(FILE *stream);
FILE *setmntent(const char *filename, const char *type);
int endmntent(FILE *stream);

#endif