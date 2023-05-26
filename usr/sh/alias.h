#ifndef _SH_ALIAS_H_
#define _SH_ALIAS_H_

#include <limits.h>

/*
 * Alias.
 */
struct alias {
	char *		name;		/* alias name */
	char *		value;		/* alias value */
};

struct alias *alias_find(const char *name);
int cmd_alias(int argc, char **argv);
int cmd_unalias(int argc, char **argv);

#endif
