#ifndef _SH_BUILTIN_H_
#define _SH_BUILTIN_H_

#include "../libreadline/readline.h"

int builtin(struct rline_ctx *ctx, int argc, char **argv, int *status);

#endif
