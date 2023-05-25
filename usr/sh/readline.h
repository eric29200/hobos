#ifndef _SH_READLINE_H_
#define _SH_READLINE_H_

#include <stdio.h>
#include <termios.h>

/*
 * Readline context.
 */
struct rline_ctx {
	struct termios	termios;	/* initial termios */
	char *		line;		/* current line */
	size_t		capacity;	/* current line capacity */
	size_t		len;		/* current line length */
	size_t		pos;		/* current position in line */
};

void rline_init_ctx(struct rline_ctx *ctx);
void rline_exit_ctx(struct rline_ctx *ctx);
ssize_t rline_readline(struct rline_ctx *ctx, char **line);

#endif