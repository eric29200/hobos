#include <unistd.h>
#include <fcntl.h>

#include "redir.h"

/*
 * Input redirection.
 */
int redir_input(struct command *command, struct command *command_prev, int pipefd[2])
{
	int fd, ret;

	/* pipe redirection */
	if (command_prev && command_prev->end_char == '|') {
		fd = pipefd[0];
		close(pipefd[1]);
		goto end;
	}

	/* input redirection */
	if (command->input) {
		fd = open(command->input, O_RDONLY, 0);
		if (fd < 0) {
			perror(command->input);
			return -1;
		}

		goto end;
	}
	
	/* no redirection */
	return STDIN_FILENO;
end:
	/* save stdin */
	ret = dup(STDIN_FILENO);
	if (ret < 0) {
		perror("dup");
		close(fd);
		return -1;
	}

	/* replace stdin */
	dup2(fd, STDIN_FILENO);

	return ret;
}

/*
 * Output redirection.
 */
int redir_output(struct command *command, int pipefd[2])
{
	int fd, ret;

	/* redirect output */
	if (command->end_char == '|') {
		/* create a pipe */
		if (pipe(pipefd) < 0) {
			perror("pipe");
			return -1;
		}

		fd = pipefd[1];
		goto end;
	}

	/* output redirection */
	if (command->output) {
		fd = open(command->output, O_CREAT | O_TRUNC | O_WRONLY, 0644);
		if (fd < 0) {
			perror(command->output);
			return -1;
		}

		goto end;
	}

	/* no redirection */
	return STDOUT_FILENO;
end:
	/* save stdout */
	ret = dup(STDOUT_FILENO);
	if (ret < 0) {
		perror("dup");
		close(fd);
		return -1;
	}

	/* replace stdout */
	dup2(fd, STDOUT_FILENO);

	return ret;
}
