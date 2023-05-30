#ifndef _SH_ALIAS_H_
#define _SH_ALIAS_H_

#include <stdbool.h>
#include <limits.h>

/*
 * Alias.
 */
struct alias {
	char *		name;		/* alias name */
	char *		value;		/* alias value */
};

extern struct alias **alias_table;
extern size_t nr_alias;

struct alias *alias_find(const char *name);
int alias_add(const char *name, char *value);
bool alias_remove(const char *name);

#endif
