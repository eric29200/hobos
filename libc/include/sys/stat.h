#ifndef _LIBC_STAT_H_
#define _LIBC_STAT_H_

#include <stdio.h>
#include <time.h>

#define S_IFMT		0170000

#define S_IFDIR		0040000
#define S_IFCHR		0020000
#define S_IFBLK		0060000
#define S_IFREG		0100000
#define S_IFIFO		0010000
#define S_IFLNK		0120000
#define S_IFSOCK	0140000

#define S_ISDIR(mode)	(((mode) & S_IFMT) == S_IFDIR)
#define S_ISCHR(mode)	(((mode) & S_IFMT) == S_IFCHR)
#define S_ISBLK(mode)	(((mode) & S_IFMT) == S_IFBLK)
#define S_ISREG(mode)	(((mode) & S_IFMT) == S_IFREG)
#define S_ISFIFO(mode)	(((mode) & S_IFMT) == S_IFIFO)
#define S_ISLNK(mode)	(((mode) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(mode)	(((mode) & S_IFMT) == S_IFSOCK)

#define S_ISUID		04000
#define S_ISGID		02000
#define S_ISVTX		01000
#define S_IRUSR		0400
#define S_IWUSR		0200
#define S_IXUSR		0100
#define S_IRWXU		0700
#define S_IRGRP		0040
#define S_IWGRP		0020
#define S_IXGRP		0010
#define S_IRWXG		0070
#define S_IROTH		0004
#define S_IWOTH		0002
#define S_IXOTH		0001
#define S_IRWXO		0007

#define S_IREAD		S_IRUSR
#define S_IWRITE	S_IWUSR
#define S_IEXEC		S_IXUSR

#define UTIME_NOW	0x3FFFFFFF
#define UTIME_OMIT	0x3FFFFFFe

/*
 * Stat64 structure.
 */
struct stat {
	unsigned long long	st_dev;
	unsigned char		__pad0[4];
	unsigned long		__st_ino;
	unsigned int		st_mode;
	unsigned int		st_nlink;
	unsigned long		st_uid;
	unsigned long		st_gid;
	unsigned long long	st_rdev;
	unsigned char		__pad3[4];
	long long		st_size;
	unsigned long		st_blksize;
	unsigned long long	st_blocks;
	unsigned long		st_atime;
	unsigned long		st_atime_nsec;
	unsigned long		st_mtime;
	unsigned int		st_mtime_nsec;
	unsigned long		st_ctime;
	unsigned long		st_ctime_nsec;
	unsigned long long	st_ino;
};

mode_t umask(mode_t mask);
int stat(const char *pathname, struct stat *statbuf);
int lstat(const char *pathname, struct stat *statbuf);
int fstat(int fd, struct stat *statbuf);
int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);
int chmod(const char *pathname, mode_t mode);
int mkdir(const char *pathname, mode_t mode);
int mknod(const char *pathname, mode_t mode, dev_t dev);

int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);

#endif
