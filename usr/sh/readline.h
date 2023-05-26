#ifndef _SH_READLINE_H_
#define _SH_READLINE_H_

#include <stdio.h>
#include <termios.h>
#include <signal.h>

#define RLINE_HISTORY_SIZE		5

/*
 * Readline history entry.
 */
struct rline_hist_entry {
	char *		line;					/* line */
	time_t		time;					/* time */
};

/*
 * Readline context.
 */
struct rline_ctx {
	struct termios			termios;		/* initial termios */
	sigset_t			sig_mask;		/* initial signal mask */
	char *				line;			/* current line */
	size_t				capacity;		/* current line capacity */
	size_t				len;			/* current line length */
	size_t				pos;			/* current position in line */
	struct rline_hist_entry **	history;		/* history */
	size_t				history_capacity;	/* history capacity */
	size_t				history_size;		/* history size */
	size_t				history_rpos;		/* history read position */
};

void rline_init_ctx(struct rline_ctx *ctx);
void rline_exit_ctx(struct rline_ctx *ctx);
ssize_t rline_readline(struct rline_ctx *ctx, char **line);

#endif