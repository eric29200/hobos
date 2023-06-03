#ifndef _LIBC_MMAN_H_
#define _LIBC_MMAN_H_

#include <stdio.h>

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);

#endif