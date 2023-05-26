#ifndef _SH_ALIAS_H_
#define _SH_ALIAS_H_

#include <limits.h>

struct alias {
	char *		name;
	char *		value;
};

struct alias *alias_find(const char *name);
int cmd_alias(int argc, char **argv);
int cmd_unalias(int argc, char **argv);

#endif
