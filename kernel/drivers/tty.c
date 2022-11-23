#include <drivers/serial.h>
#include <drivers/keyboard.h>
#include <drivers/termios.h>
#include <drivers/tty.h>
#include <drivers/pit.h>
#include <proc/sched.h>
#include <ipc/signal.h>
#include <stdio.h>
#include <stderr.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <dev.h>
#include <kd.h>

/* global ttys table */
struct tty_t tty_table[NR_TTYS];

/*
 * Lookup for a tty.
 */
static struct tty_t *tty_lookup(dev_t dev)
{
	/* current task tty */
	if (dev == DEV_TTY)
		return current_task->tty;

 	/* console = always first tty */
	if (dev == DEV_CONSOLE)
		return &tty_table[0];

	/* current active console */
	if (dev == DEV_TTY0)
		return fg_console >= 0 ? &tty_table[fg_console] : NULL;

	/* console */
	if (major(dev) == major(DEV_TTY0) && minor(dev) > 0 && minor(dev) <= NR_CONSOLES)
		return &tty_table[minor(dev) - 1];

	/* pty */
	if (major(dev) == DEV_PTS_MAJOR && minor(dev) < NR_PTYS)
		return &tty_table[NR_CONSOLES + minor(dev)];

	return NULL;
}

/*
 * Open a TTY.
 */
static int tty_open(struct file_t *filp)
{
	struct tty_t *tty;
	int noctty;
	dev_t dev;

	/* get tty */
	tty = tty_lookup(filp->f_inode->i_rdev);
	if (!tty)
		return -EINVAL;

	/* attach tty to file */
	filp->f_private = tty;

	/* get tty device number */
	dev = filp->f_inode->i_rdev;

	/* check if tty must be associated to process */
	noctty = filp->f_flags & O_NOCTTY;
	if (dev == DEV_TTY || dev == DEV_TTY0 || dev == DEV_PTMX)
		noctty = 1;

	/* associate tty */
	if (!noctty && current_task->leader) {
		current_task->tty = tty;
		tty->pgrp = current_task->pgrp;
	}

	return 0;
}

/*
 * Check tty count.
 */
static int tty_check_count(struct tty_t *tty)
{
	int count = 0, i;

	for (i = 0; i < NR_FILE; i++)
		if (filp_table[i].f_ref && filp_table[i].f_private == tty)
			count++;

	return count;
}


/*
 * Close a TTY.
 */
static int tty_close(struct file_t *filp)
{
	struct tty_t *tty = filp->f_private;

	/* specifice close */
	if (tty->driver && tty->driver->close)
		return tty->driver->close(tty);

	/* reset termios on last tty release */
	if (!tty_check_count(tty))
		tty->termios = tty->driver->termios;

	return 0;
}

/*
 * Read TTY.
 */
static int tty_read(struct file_t *filp, char *buf, int n)
{
	struct tty_t *tty;
	int count = 0;
	uint8_t c;

	/* get tty */
	tty = filp->f_private;
	if (!tty)
		return -EINVAL;

	/* read all characters */
	while (count < n) {
		/* non blocking mode : returns if no characters in cooked queue */
		if ((filp->f_flags & O_NONBLOCK) && ring_buffer_empty(&tty->cooked_queue))
			return -EAGAIN;

		/* read char */
		if (!ring_buffer_read(&tty->cooked_queue, &c, 1))
			return count ? count : -EINTR;

		/* add char to buffer */
		((unsigned char *) buf)[count++] = c;

		/* end of line : return */
		if (L_CANON(tty) && c == '\n') {
			tty->canon_data--;
			break;
		}

		/* no more characters : break */
		if (!L_CANON(tty) && ring_buffer_empty(&tty->cooked_queue))
			break;
	}

	return count;
}

/*
 * Post a character to tty.
 */
static int opost(struct tty_t *tty, uint8_t c)
{
	int space;

	/* write queue is full */
	space = ring_buffer_left(&tty->write_queue);
	if (!space)
		return -EINVAL;

	/* handle special characters */
	if (O_POST(tty)) {
		switch (c) {
			case '\n':
				if (O_NLCR(tty)) {
					if (space < 2)
						return -EINVAL;

					ring_buffer_putc(&tty->write_queue, '\r');
				}
				break;
			case '\r':
				if (O_NOCR(tty))
					return 0;
				if (O_CRNL(tty))
					c = '\n';
				break;
			default:
				if (O_LCUC(tty))
					c = TOUPPER(c);
				break;
		}
	}

	/* post character */
	ring_buffer_putc(&tty->write_queue, c);
	return 0;
}

/*
 * Output/Echo a character.
 */
static void out_char(struct tty_t *tty, uint8_t c)
{
	if (ISCNTRL(c) && !ISSPACE(c) && L_ECHOCTL(tty)) {
		opost(tty, '^');
		opost(tty, c + 64);
		tty->driver->write(tty);
	} else {
		opost(tty, c);
		tty->driver->write(tty);
	}
}

/*
 * Cook input characters.
 */
void tty_do_cook(struct tty_t *tty)
{
	uint8_t c;

	while (tty->read_queue.size > 0) {
		/* get next input character */
		ring_buffer_read(&tty->read_queue, &c, 1);

		/* convert to ascii */
		if (I_ISTRIP(tty))
			c = TOASCII(c);

		/* lower case */
		if (I_IUCLC(tty) && ISUPPER(c))
			c = TOLOWER(c);

		/* handle carriage return and new line */
		if (c == '\r') {
			/* ignore carriage return */
			if (I_IGNCR(tty))
				continue;

			/* carriage return = new line */
			if (I_ICRNL(tty))
				c = '\n';
		} else if (c == '\n' && I_INLCR(tty)) {
			c = '\r';
		}

		/* handle signals */
		if (L_ISIG(tty)) {
			if (c == tty->termios.c_cc[VINTR]) {
				task_signal_group(tty->pgrp, SIGINT);
				continue;
			}

			if (c == tty->termios.c_cc[VQUIT]) {
				task_signal_group(tty->pgrp, SIGQUIT);
				continue;
			}

			if (c == tty->termios.c_cc[VSUSP]) {
				task_signal_group(tty->pgrp, SIGSTOP);
				continue;
			}
		}

		/* echo = put character on write queue */
		if (L_ECHO(tty) && !ring_buffer_full(&tty->write_queue))
			out_char(tty, c);

		/* put character in cooked queue */
		if (!ring_buffer_full(&tty->cooked_queue))
			ring_buffer_write(&tty->cooked_queue, &c, 1);

		/* update canon data */
		if (L_CANON(tty) && c == '\n')
			tty->canon_data++;
	}

	/* wake up eventual process */
	task_wakeup(&tty->wait);
}

/*
 * Write to TTY.
 */
static int tty_write(struct file_t *filp, const char *buf, int n)
{
	struct tty_t *tty;
	int i;

	/* get tty */
	tty = filp->f_private;
	if (!tty)
		return -EINVAL;

	/* write not implemented */
	if (!tty->driver->write)
		return -EINVAL;

	/* pos characters */
	for (i = 0; i < n; i++) {
		/* put next character */
		opost(tty, buf[i]);

		/* write to tty */
		if (ring_buffer_full(&tty->write_queue) || i == n - 1)
			tty->driver->write(tty);
	}

	return n;
}

/*
 * TTY ioctl.
 */
int tty_ioctl(struct file_t *filp, int request, unsigned long arg)
{
	struct tty_t *tty;
	int ret;

	/* get tty */
	tty = filp->f_private;
	if (!tty)
		return -EINVAL;

	switch (request) {
		case TCGETS:
			memcpy((struct termios_t *) arg, &tty->termios, sizeof(struct termios_t));
			break;
		case TCSETS:
		case TCSETSW:
		case TCSETSF:
			memcpy(&tty->termios, (struct termios_t *) arg, sizeof(struct termios_t));
			tty->canon_data = 0;
			break;
		case TIOCGWINSZ:
			memcpy((struct winsize_t *) arg, &tty->winsize, sizeof(struct winsize_t));
			break;
		case TIOCSWINSZ:
			memcpy(&tty->winsize, (struct winsize_t *) arg, sizeof(struct winsize_t));
			break;
		case TIOCGPGRP:
			*((pid_t *) arg) = tty->pgrp;
			break;
		case TIOCSPGRP:
			tty->pgrp = *((pid_t *) arg);
			break;
		default:
			if (tty->driver->ioctl) {
				ret = tty->driver->ioctl(tty, request, arg);
				if (ret != -ENOIOCTLCMD)
					return ret;
			}

			printf("Unknown ioctl request (%x) on device %x\n", request, (int) filp->f_inode->i_rdev);
			break;
	}

	return 0;
}

/*
 * Check if there is some data to read.
 */
static int tty_input_available(struct tty_t *tty)
{
	if (L_CANON(tty))
		return tty->canon_data > 0;

	return tty->cooked_queue.size > 0;
}

/*
 * Poll a tty.
 */
static int tty_poll(struct file_t *filp, struct select_table_t *wait)
{
	struct tty_t *tty;
	int mask = 0;

	/* get tty */
	tty = filp->f_private;
	if (!tty)
		return -EINVAL;

	/* check if there is some characters to read */
	if (tty_input_available(tty))
		mask |= POLLIN;

	/* check if there is some characters to write */
	if (!ring_buffer_full(&tty->write_queue))
		mask |= POLLOUT;

	/* add wait queue to select table */
	select_wait(&tty->wait, wait);

	return mask;
}

/*
 * Init a tty.
 */
int tty_init_dev(struct tty_t *tty, struct tty_driver_t *driver)
{
	int ret;

	memset(tty, 0, sizeof(struct tty_t));
	tty->driver = driver;

	/* init read queue */
	ret = ring_buffer_init(&tty->read_queue, TTY_BUF_SIZE);
	if (ret)
		return ret;

	/* init write queue */
	ret = ring_buffer_init(&tty->write_queue, TTY_BUF_SIZE);
	if (ret)
		return ret;

	/* init cooked queue */
	ret = ring_buffer_init(&tty->cooked_queue, TTY_BUF_SIZE);
	if (ret)
		return ret;

	/* init termios */
	tty->termios = driver->termios;

	return 0;
}

/*
 * Destroy a tty.
 */
void tty_destroy(struct tty_t *tty)
{
	ring_buffer_destroy(&tty->read_queue);
	ring_buffer_destroy(&tty->write_queue);
	ring_buffer_destroy(&tty->cooked_queue);
}

/*
 * Init TTYs.
 */
int init_tty(struct multiboot_tag_framebuffer *tag_fb)
{
	int ret;

	/* reset ttys */
	memset(tty_table, 0, sizeof(struct tty_t) * NR_TTYS);

	/* init consoles */
	ret = init_console(tag_fb);
	if (ret)
		return ret;

	/* init ptys */
	init_pty();

	return 0;
}

/*
 * Tty file operations.
 */
static struct file_operations_t tty_fops = {
	.open		= tty_open,
	.close		= tty_close,
	.read		= tty_read,
	.write		= tty_write,
	.poll		= tty_poll,
	.ioctl		= tty_ioctl,
};

/*
 * Tty inode operations.
 */
struct inode_operations_t tty_iops = {
	.fops		= &tty_fops,
};
