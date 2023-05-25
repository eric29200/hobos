#ifndef _SH_CMD_H_
#define _SH_CMD_H_

#include "readline.h"

int cmd_builtin(struct rline_ctx *ctx, int argc, char **argv, int *status);

#endif
