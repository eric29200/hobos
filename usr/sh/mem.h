#ifndef _SH_MEM_H_
#define _SH_MEM_H_

void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

#endif
