#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <sys/wait.h>

#include "command.h"
#include "builtin.h"
#include "alias.h"
#include "job.h"
#include "mem.h"

/* temporary buffer */
static char *__buf = NULL;
static size_t __bufsize = 0;

/*
 * Add a character to temporary buffer.
 */
static void add_char(char c, size_t pos)
{
	/* grow buffer if needed */
	if (pos >= __bufsize) {
		__bufsize = ALIGN_UP(pos + 1, 64);
		__buf = (char *) xrealloc(__buf, __bufsize);
	}

	__buf[pos] = c;
}

/*
 * Add an argument to a command.
 */
static void command_add_arg(struct command *command, char *arg, size_t arglen, char redir)
{
	char *arg_cp = NULL;

	/* input redirection */
	if (redir == 'i') {
		if (!command->input)
			command->input = xstrndup(arg, arglen);
		return;
	}

	/* output redirection */
	if (redir == 'o') {
		if (!command->output)
			command->output = xstrndup(arg, arglen);
		return;
	}

	/* grow argv if needed */
	if (command->argc >= command->argv_capacity) {
		command->argv_capacity += 8;
		command->argv = (char **) xrealloc(command->argv, sizeof(char *) * command->argv_capacity);
	}

	/* add argument */
	if (arg)
		arg_cp = xstrndup(arg, arglen);

	/* add argument */
	command->argv[command->argc++] = arg_cp;
}

/*
 * Clear a command.
 */
void command_clear(struct command *command)
{
	int i;

	/* free command line */
	if (command->cmdline)
		free(command->cmdline);

	/* free arguments */
	for (i = 0; i < command->argc; i++)
		if (command->argv[i])
			free(command->argv[i]);
	command->argc = 0;

	/* free input file */
	if (command->input) {
		free(command->input);
		command->input = NULL;
	}

	/* free output file */
	if (command->output) {
		free(command->output);
		command->output = NULL;
	}
}

/*
 * Make command line.
 */
static void command_make_cmdline(struct command *command, char *cmd, size_t cmdlen)
{
	struct alias *alias = NULL;
	char *c, *v, quoted = 0;
	size_t n = 0;

	/* get argv[0] */
	for (c = cmd; *c && c < cmd + cmdlen; c++) {
		switch (*c) {
			case ' ':
			case '\t':
				if (quoted)
					goto __add_char;
				if (n > 0)
					goto end;
				continue;
			case '>':
				if (quoted)
					goto __add_char;
				goto end;
			case '<':
				if (quoted)
					goto __add_char;
				goto end;
			case '\'':
			case '\"':
				if (quoted == *c)
					quoted = 0;
				else if (!quoted)
					quoted = *c;
				else
					goto __add_char;

				continue;
			default:
				goto __add_char;
		}

		continue;
__add_char:
		add_char(*c, n++);
		continue;
	}

end:
	/* empty argv[0] */
	if (n == 0)
		goto dup_cmdline;

	/* try to find an alias */
	add_char(0, n);
	alias = alias_find(__buf);
	if (!alias)
		goto dup_cmdline;

	/* start command line with alias value */
	for (v = alias->value, n = 0; *v; v++)
		add_char(*v, n++);

	/* add remaining command line */
	for (; c < cmd + cmdlen; c++)
		add_char(*c, n++);

	/* set command line */
	command->cmdline = xstrndup(__buf, n);
	return;
dup_cmdline:
	command->cmdline = xstrndup(cmd, cmdlen);
}

/*
 * Parse a command.
 */
int command_parse(struct command *command, char *cmd, size_t cmdlen)
{
	char quoted = 0, redir = 0, *c;
	size_t n = 0;

	/* make command line */
	command_make_cmdline(command, cmd, cmdlen);

	/* parse command */
	for (c = command->cmdline; *c; c++) {
		switch (*c) {
			case ' ':
			case '\t':
				if (quoted)
					goto __add_char;
				goto __add_arg;
			case '>':
				if (quoted)
					goto __add_char;
				if (n > 0)
					command_add_arg(command, __buf, n, redir);
				n = 0;
				redir = 'o';
				continue;
			case '<':
				if (quoted)
					goto __add_char;
				if (n > 0)
					command_add_arg(command, __buf, n, redir);
				n = 0;
				redir = 'i';
				continue;
			case '\'':
			case '\"':
				if (quoted == *c)
					quoted = 0;
				else if (!quoted)
					quoted = *c;
				else
					goto __add_char;

				continue;
			default:
				goto __add_char;
		}

		continue;
__add_arg:
		if (n > 0)
			command_add_arg(command, __buf, n, redir);
		n = 0;
		continue;
__add_char:
		add_char(*c, n++);
		continue;
	}

	/* add last argument */
	if (n > 0)
		command_add_arg(command, __buf, n, redir);

	/* end argv */
	command_add_arg(command, NULL, 0, 0);

	/* argc - 1 (for last NULL argument) */
	command->argc--;

	return 0;
}