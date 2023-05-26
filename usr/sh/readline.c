#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <termios.h>

#include "readline.h"

#define LINE_GROW_SIZE		64

#define ESCAPE			27

#define KEY_TAB			9
#define KEY_ENTER		10
#define KEY_DELETE		51
#define KEY_UP			65
#define KEY_DOWN		66
#define KEY_RIGHT		67
#define KEY_LEFT		68
#define KEY_END			70
#define KEY_HOME		72
#define KEY_BACKSPACE		127

/*
 * Allocate an history entry.
 */
static struct rline_hist_entry *rline_history_alloc_entry(const char *line)
{
	struct rline_hist_entry *entry;

	/* alloc entry */
	entry = (struct rline_hist_entry *) malloc(sizeof(struct rline_hist_entry));
	if (!entry)
		return NULL;

	/* set line */
	entry->line = strdup(line);
	if (!entry->line) {
		free(entry);
		return NULL;
	}

	/* set time */
	entry->time = time(NULL);

	return entry;
}

/*
 * Free an history entry.
 */
static void rline_history_free_entry(struct rline_hist_entry *entry)
{
	if (entry) {
		if (entry->line)
			free(entry->line);

		free(entry);
	}
}

/*
 * Save a line in history.
 */
static void rline_history_save_line(struct rline_ctx *ctx, const char *line)
{
	struct rline_hist_entry *entry;

	/* history full */
	if (ctx->history_size == ctx->history_capacity) {
		/* no history */
		if (!ctx->history_capacity)
			return;

		/* remove first entry */
		if (ctx->history[0])
			rline_history_free_entry(ctx->history[0]);

		/* shift other entries on the left */
		memmove(ctx->history, ctx->history + 1, ctx->history_size * sizeof(struct rline_hist_entry *));

		/* update history size */
		ctx->history_size--;
	}

	/* allocate a new entry */
	entry = rline_history_alloc_entry(line);
	if (!entry)
		return;

	/* save entry in history */
	ctx->history[ctx->history_size++] = entry;

	/* reset read position */
	ctx->history_rpos = 0;
}

static void move_left(int n);

/*
 * Load a line from history.
 */
static void rline_history_load_line(struct rline_ctx *ctx, int pos)
{
	size_t i;

	/* clear current line */
	if (ctx->pos > 0) {
		move_left(ctx->pos);
		for (i = 0; i < ctx->len; i++)
			fputc(' ', stdout);
		move_left(ctx->len);
	}

	/* copy history line */
	strcpy(ctx->line, ctx->history[ctx->history_size - pos]->line);

	/* set length/position */
	ctx->len = strlen(ctx->line);
	ctx->pos = ctx->len;

	/* render line */
	printf("%s", ctx->line);
}

/*
 * Move to (n < 0 = left, n > 0 = right).
 */
static void move_to(int n)
{
	if (n > 0)
		printf("\x1B[%dC", n);
	else if (n < 0)
		printf("\x1B[%dD", -n);
}

/*
 * Move left.
 */
static void move_left(int n)
{
	move_to(-n);
}

/*
 * Move right.
 */
static void move_right(int n)
{
	move_to(n);
}

/*
 * Move to start of line.
 */
static void move_start_line(struct rline_ctx *ctx)
{
	move_left(ctx->pos);
	ctx->pos = 0;
}

/*
 * Move to end of line.
 */
static void move_end_line(struct rline_ctx *ctx)
{
	move_right(ctx->len - ctx->pos);
	ctx->pos = ctx->len;
}

/*
 * Move cursor.
 */
static void move_cursor(struct rline_ctx *ctx, int direction)
{
	if ((int) ctx->pos + direction < 0 || ctx->pos + direction > ctx->len)
		return;

	ctx->pos += direction;
	move_to(direction);
}

/*
 * Add a character.
 */
static int add_char(struct rline_ctx *ctx, int c)
{
	size_t i;

	/* grow line if needed */
	if (ctx->len + 2 >= ctx->capacity) {
		ctx->capacity += LINE_GROW_SIZE;
		ctx->line = (char *) realloc(ctx->line, sizeof(char) * ctx->capacity);
		if (!ctx->line)
			return -1;
	}

	/* append character */
	if (ctx->pos == ctx->len) {
		ctx->line[ctx->len] = c;
		goto end;
	}

	/* right shift characters */
	for (i = ctx->len; i > ctx->pos; i--)
		ctx->line[i] = ctx->line[i - 1];
	ctx->line[i] = c;

end:
	/* render line */
	fwrite(ctx->line + ctx->pos, 1, ctx->len + 1 - ctx->pos, stdout);

	/* update line length/position */
	ctx->len++;
	ctx->pos++;

	/* end line */
	ctx->line[ctx->len] = 0;

	/* move cursor */
	if (ctx->pos < ctx->len)
		move_to(-(ctx->len - ctx->pos));

	return 0;
}

/*
 * Delete a character.
 */
static void delete_char(struct rline_ctx *ctx, int move_pos)
{
	size_t i;

	/* check position */
	if ((int) ctx->pos + move_pos < 0 || ctx->pos + move_pos >= ctx->len)
		return;

	/* left shift characters */
	ctx->pos += move_pos;
	for (i = ctx->pos; i < ctx->len - 1; i++)
		ctx->line[i] = ctx->line[i + 1];

	/* update line length */
	ctx->len--;
	ctx->line[ctx->len] = 0;

	/* render line */
	move_to(move_pos);
	fwrite(ctx->line + ctx->pos, 1, ctx->len - ctx->pos, stdout);
	fputc(' ', stdout);
	move_left(ctx->len - ctx->pos + 1);
}

/*
 * Handle an escape sequence.
 */
static void handle_escape_sequence(struct rline_ctx *ctx)
{
	/* sequence must begin with '[' */
	if (getc(stdin) != '[')
		return;

	switch (getc(stdin)) {
		case KEY_DELETE:
			getc(stdin);
			delete_char(ctx, 0);
			break;
		case KEY_UP:
		  	if (ctx->history_rpos < ctx->history_size)
		 		rline_history_load_line(ctx, ++ctx->history_rpos);
			break;
		case KEY_DOWN:
		  	if (ctx->history_rpos > 0)
		 		rline_history_load_line(ctx, --ctx->history_rpos);
			break;
		case KEY_LEFT:
			move_cursor(ctx, -1);
			break;
		case KEY_RIGHT:
			move_cursor(ctx, 1);
			break;
		case KEY_HOME:
			move_start_line(ctx);
			break;
		case KEY_END:
			move_end_line(ctx);
			break;
		case '1':
			if (getc(stdin) == '~')
				move_start_line(ctx);
			break;
		case '4':
			if (getc(stdin) == '~')
				move_end_line(ctx);
			break;
		default:
			break;
	}
}

/*
 * Set read mode.
 */
static void rline_set_read_mode(struct rline_ctx *ctx)
{
	struct termios termios;

	/* save termios */
	tcgetattr(STDOUT_FILENO, &ctx->termios);

	/* disable canonical mode, input echo and signals */
	memcpy(&termios, &ctx->termios, sizeof(struct termios));
	termios.c_lflag &= ~(ICANON | ECHO | ISIG);
	tcsetattr(STDOUT_FILENO, TCSAFLUSH, &termios);
}

/*
 * Unset read mode.
 */
static void rline_unset_read_mode(struct rline_ctx *ctx)
{
	/* restore initial termios */
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &ctx->termios);
}

/*
 * Read a line.
 */
ssize_t rline_readline(struct rline_ctx *ctx, char **line)
{
	ssize_t ret = -1;
	int c;

	/* set read mode */
	rline_set_read_mode(ctx);

	/* reset line */
	ctx->len = ctx->pos = 0;
	*line = NULL;

	for (;;) {
		/* get next character */
		c = getc(stdin);
		if (c < 0)
			goto err;

		switch (c) {
			case KEY_ENTER:
				fputc('\n', stdout);
				goto out;
			case KEY_TAB:
				break;
			case KEY_BACKSPACE:
				delete_char(ctx, -1);
				break;
			case ESCAPE:
				handle_escape_sequence(ctx);
				break;
			default:
				if (c >= ' ' && add_char(ctx, c))
					goto err;

				break;
		}

		/* flush stdout */
		fflush(stdout);
	}

out:
	/* set output line */
	*line = ctx->line;
	ret = ctx->len;

	/* save line in history */
	if (ctx->len > 0)
		rline_history_save_line(ctx, *line);
err:
	rline_unset_read_mode(ctx);
	return ret;
}

/*
 * Init a readline context.
 */
void rline_init_ctx(struct rline_ctx *ctx)
{
	size_t i;

	/* reset context */
	memset(ctx, 0, sizeof(struct rline_ctx));

	/* allocate history */
	ctx->history = (struct rline_hist_entry **) malloc(sizeof(struct rline_hist_entry *) * RLINE_HISTORY_SIZE);
	if (!ctx->history)
		return;

	/* reset history */
	ctx->history_capacity = RLINE_HISTORY_SIZE;
	for (i = 0; i < ctx->history_capacity; i++)
		ctx->history[i] = NULL;
}

/*
 * Exit a readline context.
 */
void rline_exit_ctx(struct rline_ctx *ctx)
{
	size_t i;

	if (ctx) {
		/* free current line */
		if (ctx->line)
			free(ctx->line);

		/* free history */
		if (ctx->history) {
			for (i = 0; i < ctx->history_size; i++)
				rline_history_free_entry(ctx->history[i]);

			free(ctx->history);
		}

		/* reset context */
		memset(ctx, 0, sizeof(struct rline_ctx));
	}
}
