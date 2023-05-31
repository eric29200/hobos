#ifndef _SH_COMMAND_H_
#define _SH_COMMAND_H_

#include <stdio.h>

#include "../libreadline/readline.h"

/*
 * Command.
 */
struct command {
	char *			cmdline;	/* command line */
	char **			argv;		/* arguments */
	int			argv_capacity;	/* argv capacity */
	int			argc;		/* number of arguments */
	char *			input;		/* input redirection */
	char *			output;		/* output redirection */
	char			end_char;	/* end character (& or ; or |) */
};

int command_parse(struct command *command, char *cmd, size_t cmdlen);
void command_clear(struct command *command);
int command_execute(struct command *command, struct rline_ctx *ctx);

#endif
