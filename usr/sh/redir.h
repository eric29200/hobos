#ifndef _SH_REDIR_H_
#define _SH_REDIR_H_

#include "command.h"

int redir_input(struct command *command, struct command *command_prev, int pipefd[2]);
int redir_output(struct command *command, int pipefd[2]);

#endif