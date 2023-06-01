#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <sys/wait.h>

#include "pipeline.h"
#include "job.h"
#include "mem.h"

/*
 * Add a command to pipeline.
 */
static int pipeline_add_command(struct pipeline *line, char *cmd, size_t cmdlen, char end_char)
{
	struct command *command;

	/* grow commands array if needed */
	if (line->cmds_size >= line->cmds_capacity) {
		line->cmds_capacity += 8;
		line->cmds = (struct command *) xrealloc(line->cmds, sizeof(struct command) * line->cmds_capacity);
	}

	/* get command */
	command = &line->cmds[line->cmds_size++];
	memset(command, 0, sizeof(struct command));
	command->end_char = end_char;

	/* parse command */
	return command_parse(command, cmd, cmdlen);
}

/*
 * Clear a pipeline.
 */
void pipeline_clear(struct pipeline *line)
{
	size_t i;

	if (!line)
		return;

	for (i = 0; i < line->cmds_size; i++)
		command_clear(&line->cmds[i]);

	line->cmds_size = 0;

	if (line->cmdline)
		free(line->cmdline);
}

/*
 * Parse a command line.
 */
int pipeline_parse(struct pipeline *line, char *cmdline)
{
	char *start, *end;
	char quoted = 0;
	int ret;

	/* check command line */
	if (!cmdline)
		return -1;

	/* duplicate command line */
	line->cmdline = xstrdup(cmdline);

	/* skip first spaces */
	for (start = cmdline; isspace(*start); start++);

	/* full comment */
	if (!*start || *start == '#')
		return 0;

	/* find end of command */
	for (end = start; *end; end++) {
		switch (*end) {
			case ';':
			case '&':
			case '|':
				/* end of command */
				if (!quoted) {
					/* add command */
					ret = pipeline_add_command(line, start, end - start, *end);
					if (ret)
						return ret;

					/* set next command */
					start = end + 1;
				}

				break;
			case '\'':
			case '\"':
				if (*end == '\'' || *end == '\"') {
					if (quoted == *end)
						quoted = 0;
					else if (!quoted)
						quoted = *end;
				}

				break;
		}
	}

	/* parse last command */
	if (end > start)
		return pipeline_add_command(line, start, end - start, 0);

	return 0;
}

static int redir_input(struct command *command)
{
	int fd_in, ret;

	if (!command->input)
		return STDIN_FILENO;

	/* open input file */
	fd_in = open(command->input, O_RDONLY, 0);
	if (fd_in < 0) {
		perror(command->input);
		return -1;
	}

	/* save stdin */
	ret = dup(STDIN_FILENO);
	if (ret < 0) {
		close(fd_in);
		return -1;
	}

	/* replace stdin */
	dup2(fd_in, STDIN_FILENO);

	return ret;
}

static int redir_output(struct command *command)
{
	int fd_out, ret;

	if (!command->output)
		return STDOUT_FILENO;

	/* open output file */
	fd_out = open(command->output, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd_out < 0) {
		perror(command->output);
		return -1;
	}

	/* save stdout */
	ret = dup(STDOUT_FILENO);
	if (ret < 0) {
		close(fd_out);
		return -1;
	}

	/* replace stdout */
	dup2(fd_out, STDOUT_FILENO);

	return ret;
}

/*
 * Execute a pipeline.
 */
int pipeline_execute(struct pipeline *line, struct rline_ctx *ctx)
{
	int ret = 0, status, fd_stdin, fd_stdout;
	struct command *command;
	struct job *job;
	size_t i;

	for (i = 0; i < line->cmds_size; i++) {
		/* get command */
		command = &line->cmds[i];

		/* redir input */
		fd_stdin = redir_input(command);
		if (fd_stdin < 0) {
			ret = -1;
			goto next;
		}

		/* redir output */
		fd_stdout = redir_output(command);
		if (fd_stdout < 0) {
			ret = -1;
			goto next;
		}

		/* submit job */
		job = job_submit(command, ctx);
		if (!job) {
			ret = -1;
			goto next;
		}

		/* wait for job */
		if (command->end_char != '&') {
			/* wait for job */
			while ((ret = waitpid(job->pid, &status, 0)) == 0);

			/* no matching child : sigchld probably got it */
			if (ret < 0 && errno != ECHILD)
				perror("waitpid");

			/* free job */	
			job_free(job);
		}

next:
		/* restore stdin */
		if (fd_stdin >= 0 && fd_stdin != STDIN_FILENO) {
			close(STDIN_FILENO);
			dup2(fd_stdin, STDIN_FILENO);
		}

		/* restore stdout */
		if (fd_stdout >= 0 && fd_stdout != STDOUT_FILENO) {
			close(STDOUT_FILENO);
			dup2(fd_stdout, STDOUT_FILENO);
		}
	}

	return ret;
}
