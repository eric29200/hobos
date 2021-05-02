#ifndef _UNISTD_H_
#define _UNISTD_H_

#include <sys/types.h>
#include <sys/stat.h>

#define __NR_exit         1
#define __NR_fork         2
#define __NR_read         3
#define __NR_write        4
#define __NR_open         5
#define __NR_close        6
#define __NR_stat         7
#define __NR_execve       8
#define __NR_sbrk         9
#define __NR_sleep        10
#define __NR_dup          11
#define __NR_dup2         12
#define __NR_wait         13
#define __NR_access       14

/*
 * System call with no argument.
 */
static inline int syscall0(int n)
{
  int ret;
  __asm__ __volatile__("int $0x80" : "=a" (ret) : "0" (n));
  return ret;
}

/*
 * System call with 1 argument.
 */
static inline int syscall1(int n, int p1)
{
  int ret;
  __asm__ __volatile__("int $0x80" : "=a" (ret) : "0" (n), "b" (p1));
  return ret;
}

/*
 * System call with 2 arguments.
 */
static inline int syscall2(int n, int p1, int p2)
{
  int ret;
  __asm__ __volatile__("int $0x80" : "=a" (ret) : "0" (n), "b" (p1), "c" (p2));
  return ret;
}

/*
 * System call with 3 arguments.
 */
static inline int syscall3(int n, int p1, int p2, int p3)
{
  int ret;
  __asm__ __volatile__("int $0x80" : "=a" (ret) : "0" (n), "b" (p1), "c" (p2), "d" (p3));
  return ret;
}

/*
 * Exit system call.
 */
static inline void exit(int status)
{
  syscall1(__NR_exit, status);
}

/*
 * Fork system call.
 */
static inline pid_t fork()
{
  return syscall0(__NR_fork);
}

/*
 * Read system call.
 */
static inline ssize_t read(int fd, void *buf, size_t count)
{
  return syscall3(__NR_read, fd, (int) buf, count);
}

/*
 * Write system call.
 */
static inline ssize_t write(int fd, void *buf, size_t count)
{
  return syscall3(__NR_write, fd, (int) buf, count);
}

/*
 * Open system call.
 */
static inline int open(const char *pathname)
{
  return syscall1(__NR_open, (int) pathname);
}

/*
 * Close system call.
 */
static inline int close(int fd)
{
  return syscall1(__NR_close, fd);
}

/*
 * Stat system call.
 */
static inline int stat(const char *pathname, struct stat *statbuf)
{
  return syscall2(__NR_stat, (int) pathname, (int) statbuf);
}

/*
 * Execve system call.
 */
static inline int execve(const char *path, char *const argv[], char *const envp[])
{
  return syscall3(__NR_execve, (int) path, (int) argv, (int) envp);
}

/*
 * Sbrk system call.
 */
static inline void *sbrk(size_t n)
{
  return (void *) syscall1(__NR_sbrk, n);
}

/*
 * Sleep system call.
 */
static inline int sleep(unsigned long sec)
{
  return syscall1(__NR_sleep, sec);
}

/*
 * Dup system call.
 */
static inline int dup(int oldfd)
{
  return syscall1(__NR_dup, oldfd);
}

/*
 * Dup2 system call.
 */
static inline int dup2(int oldfd, int newfd)
{
  return syscall2(__NR_dup2, oldfd, newfd);
}

/*
 * Wait system call.
 */
static inline int wait()
{
  return syscall0(__NR_wait);
}

/*
 * Access system call.
 */
static inline int access(const char *pathname)
{
  return syscall1(__NR_access, (int) pathname);
}

#endif
