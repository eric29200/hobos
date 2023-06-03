#ifndef _LIBC_SYSCALL_H_
#define _LIBC_SYSCALL_H_

#include <errno.h>

static inline long __syscall_ret(long ret)
{
	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	errno = 0;
	return ret;
}

static inline long __syscall0(long nr)
{
	long ret;
	__asm__ __volatile__("int $0x80" : "=a"(ret) : "0"(nr));
	return ret;
}

static inline long __syscall1(long nr, long a1)
{
	long ret;
	__asm__ __volatile__("int $0x80" : "=a"(ret) : "0"(nr), "b"(a1));
	return ret;
}

static inline long __syscall2(long nr, long a1, long a2)
{
	long ret;
	__asm__ __volatile__("int $0x80" : "=a"(ret) : "0"(nr), "b"(a1), "c"(a2));
	return ret;
}

static inline long __syscall3(long nr, long a1, long a2, long a3)
{
	long ret;
	__asm__ __volatile__("int $0x80" : "=a"(ret) : "0"(nr), "b"(a1), "c"(a2), "d"(a3));
	return ret;
}

static inline long __syscall4(long nr, long a1, long a2, long a3, long a4)
{
	long ret;
	__asm__ __volatile__("int $0x80" : "=a"(ret) : "0"(nr), "b"(a1), "c"(a2), "d"(a3), "S"(a4));
	return ret;
}

static inline long __syscall5(long nr, long a1, long a2, long a3, long a4, long a5)
{
	long ret;
	__asm__ __volatile__("int $0x80" : "=a"(ret) : "0"(nr), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5));
	return ret;
}

static inline long __syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	long ret;
	__asm__ __volatile__ ("pushl %7 ; push %%ebp ; mov 4(%%esp),%%ebp ; int $0x80 ; pop %%ebp ; add $4,%%esp"
		: "=a"(ret) : "a"(nr), "b"(a1), "c"(a2), "d"(a3), "S"(a4), "D"(a5), "g"(a6) : "memory");
	return ret;
}

static inline long syscall0(long nr)
{
	return __syscall_ret(__syscall0(nr));
}

static inline long syscall1(long nr, long a1)
{
	return __syscall_ret(__syscall1(nr, a1));
}

static inline long syscall2(long nr, long a1, long a2)
{
	return __syscall_ret(__syscall2(nr, a1, a2));
}

static inline long syscall3(long nr, long a1, long a2, long a3)
{
	return __syscall_ret(__syscall3(nr, a1, a2, a3));
}

static inline long syscall4(long nr, long a1, long a2, long a3, long a4)
{
	return __syscall_ret(__syscall4(nr, a1, a2, a3, a4));
}

static inline long syscall5(long nr, long a1, long a2, long a3, long a4, long a5)
{
	return __syscall_ret(__syscall5(nr, a1, a2, a3, a4, a5));
}

static inline long syscall6(long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
	return __syscall_ret(__syscall6(nr, a1, a2, a3, a4, a5, a6));
}

#endif