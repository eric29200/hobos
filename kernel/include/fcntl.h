#ifndef _FCNTL_H_
#define _FCNTL_H_

#define S_IFMT        0170000
#define S_IFREG       0100000
#define S_IFBLK       0060000
#define S_IFDIR       0040000
#define S_IFCHR       0020000
#define S_IFIFO       0010000
#define S_ISUID       04000
#define S_ISGID       02000
#define S_ISVTX       01000

#define S_ISREG(m)	  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)	  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)	  (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m)	  (((m) & S_IFMT) == S_IFIFO)

#define S_IRWXU       0700
#define S_IRUSR       0400
#define S_IWUSR       0200
#define S_IXUSR       0100

#define S_IRWXG       0070
#define S_IRGRP       0040
#define S_IWGRP       0020
#define S_IXGRP       0010

#define S_IRWXO       0007
#define S_IROTH       0004
#define S_IWOTH       0002
#define S_IXOTH       0001

#define SEEK_SET      0
#define SEEK_CUR      1
#define SEEK_END      2

#define O_PATH        010000000
#define O_SEARCH      O_PATH
#define O_RDONLY      00
#define O_WRONLY      01
#define O_RDWR        02
#define O_ACCMODE     (03 | O_SEARCH)
#define O_CREAT       0100
#define O_TRUNC       01000
#define O_EXCL        0200
#define O_NOCTTY      0400

#endif
