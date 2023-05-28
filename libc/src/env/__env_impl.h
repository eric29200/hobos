#ifndef _LIBC_ENV_IMPL_H_
#define _LIBC_ENV_IMPL_H_

void __env_rm_add(char *old, char *new);
int __putenv(char *s, size_t len, char *r);

#endif