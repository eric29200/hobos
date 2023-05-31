#ifndef _SH_PIPELINE_H_
#define _SH_PIPELINE_H_

#include "command.h"

#include "../libreadline/readline.h"

/*
 * Pipeline = following commands.
 */
struct pipeline {
	char *			cmdline;	/* initial command line */
	struct command *	cmds;		/* commands */
	size_t			cmds_capacity;	/* commands capacity */
	size_t			cmds_size;	/* number of commands */
};

int pipeline_parse(struct pipeline *line, char *cmdline);
void pipeline_clear(struct pipeline *line);
int pipeline_execute(struct pipeline *line, struct rline_ctx *ctx);

#endif
