#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "utils.h"

/*
 * Input redirection.
 */
int redir_input(char *cmd)
{
	char *tokens[2], *filename;
	int fd;

	if (tokenize(cmd, tokens, 2, "<") <= 1)
		return STDIN_FILENO;

	/* trim filename */
	filename = strtok(tokens[1], " ");

	/* open input file */
	fd = open(filename, O_RDONLY, 0);
	if (fd < 0) {
		perror(filename);
		return -1;
	}

	return fd;
}

/*
 * Output redirection.
 */
int redir_output(char *cmd)
{
	char *tokens[2], *filename;
	int fd;

	if (tokenize(cmd, tokens, 2, ">") <= 1)
		return STDOUT_FILENO;

	/* trim filename */
	filename = strtok(tokens[1], " ");

	/* open output file */
	fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0) {
		perror(filename);
		return -1;
	}

	return fd;
}