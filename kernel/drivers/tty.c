#include <drivers/serial.h>
#include <drivers/keyboard.h>
#include <drivers/termios.h>
#include <drivers/tty.h>
#include <drivers/console.h>
#include <drivers/pit.h>
#include <proc/sched.h>
#include <proc/timer.h>
#include <ipc/signal.h>
#include <stdio.h>
#include <stderr.h>
#include <time.h>
#include <dev.h>

#define NB_TTYS         4

/* global ttys */
static struct tty_t tty_table[NB_TTYS];
static int current_tty;
static struct timer_event_t refresh_tm;

/*
 * Lookup for a tty.
 */
static struct tty_t *tty_lookup(dev_t dev)
{
  int i;

  /* current task tty */
  if (dev == DEV_TTY) {
    dev = tty_get();

    for (i = 0; i < NB_TTYS; i++)
      if (current_task->tty == tty_table[i].dev)
        return &tty_table[i];

    return NULL;
  }

  /* current active tty */
  if (dev == DEV_TTY0)
    return &tty_table[current_tty];

  /* asked tty */
  if (minor(dev) > 0 && minor(dev) <= NB_TTYS)
    return &tty_table[minor(dev) - 1];

  return NULL;
}

/*
 * Read TTY.
 */
size_t tty_read(dev_t dev, void *buf, size_t n)
{
  struct tty_t *tty;
  size_t count = 0;
  int key;

  /* get tty */
  tty = tty_lookup(dev);
  if (!tty)
    return -EINVAL;

  /* reset read/write positions on canonical mode */
  if (L_CANON(tty)) {
    tty->r_pos = 0;
    tty->w_pos = 0;
  }

  /* read all characters */
  while (count < n) {
    /* wait for a character */
    while (tty->r_pos >= tty->w_pos)
      task_sleep(tty);

    /* get key */
    key = tty->buf[tty->r_pos++];

    /* add key to buffer */
    ((unsigned char *) buf)[count++] = key;

    /* end of line : return */
    if (key == '\n')
      break;
  }

  return count;
}

/*
 * Get current task tty.
 */
dev_t tty_get()
{
  int i;

  for (i = 0; i < NB_TTYS; i++)
    if (tty_table[i].pgrp == current_task->pgid)
      return tty_table[i].dev;

  return (dev_t) -ENOENT;
}

/*
 * Write a character to tty.
 */
void tty_update(unsigned char c)
{
  struct tty_t *tty;
  uint8_t *buf;
  int len;

  /* get tty */
  tty = &tty_table[current_tty];

  /* adjust read position */
  if (tty->w_pos >= TTY_BUF_SIZE) {
    tty->r_pos = 0;
    tty->w_pos = 0;
  }

  /* set buffer */
  len = 0;
  buf = &tty->buf[tty->w_pos];

  /* handle special keys */
  switch (c) {
    case KEY_PAGEUP:
      tty->buf[tty->w_pos++] = 27;
      tty->buf[tty->w_pos++] = 91;
      tty->buf[tty->w_pos++] = 53;
      tty->buf[tty->w_pos++] = 126;
      len = 4;
      break;
    case KEY_PAGEDOWN:
      tty->buf[tty->w_pos++] = 27;
      tty->buf[tty->w_pos++] = 91;
      tty->buf[tty->w_pos++] = 54;
      tty->buf[tty->w_pos++] = 126;
      len = 4;
      break;
    case KEY_HOME:
      tty->buf[tty->w_pos++] = 27;
      tty->buf[tty->w_pos++] = 91;
      tty->buf[tty->w_pos++] = 72;
      len = 3;
      break;
    case KEY_END:
      tty->buf[tty->w_pos++] = 27;
      tty->buf[tty->w_pos++] = 91;
      tty->buf[tty->w_pos++] = 70;
      len = 3;
      break;
    case KEY_INSERT:
      tty->buf[tty->w_pos++] = 27;
      tty->buf[tty->w_pos++] = 91;
      tty->buf[tty->w_pos++] = 50;
      tty->buf[tty->w_pos++] = 126;
      len = 4;
      break;
    case KEY_DELETE:
      tty->buf[tty->w_pos++] = 27;
      tty->buf[tty->w_pos++] = 91;
      tty->buf[tty->w_pos++] = 51;
      tty->buf[tty->w_pos++] = 126;
      len = 4;
      break;
    case KEY_UP:
      tty->buf[tty->w_pos++] = 27;
      tty->buf[tty->w_pos++] = 91;
      tty->buf[tty->w_pos++] = 65;
      len = 3;
      break;
    case KEY_DOWN:
      tty->buf[tty->w_pos++] = 27;
      tty->buf[tty->w_pos++] = 91;
      tty->buf[tty->w_pos++] = 66;
      len = 3;
      break;
    case KEY_RIGHT:
      tty->buf[tty->w_pos++] = 27;
      tty->buf[tty->w_pos++] = 91;
      tty->buf[tty->w_pos++] = 67;
      len = 3;
      break;
    case KEY_LEFT:
      tty->buf[tty->w_pos++] = 27;
      tty->buf[tty->w_pos++] = 91;
      tty->buf[tty->w_pos++] = 68;
      len = 3;
      break;
    default:
      tty->buf[tty->w_pos++] = c;
      len = 1;
      break;
  }

  /* echo character on device */
  if (L_ECHO(tty) && len > 0)
    tty_write(tty->dev, (char *) buf, len);

  /* wake up eventual process */
  task_wakeup(tty);
}

/*
 * Write to TTY.
 */
int tty_write(dev_t dev, const char *buf, int n)
{
  struct tty_t *tty;

  /* get tty */
  tty = tty_lookup(dev);
  if (!tty)
    return -EINVAL;

  /* write not implemented */
  if (!tty->write)
    return -EINVAL;

  return tty->write(tty, buf, n);
}

/*
 * Change current tty.
 */
void tty_change(uint32_t n)
{
  if (n < NB_TTYS) {
    current_tty = n;
    tty_table[current_tty].fb.dirty = 1;
  }
}

/*
 * TTY ioctl.
 */
int tty_ioctl(dev_t dev, int request, unsigned long arg)
{
  struct tty_t *tty;

  /* get tty */
  tty = tty_lookup(dev);
  if (!tty)
    return -EINVAL;

  switch (request) {
    case TCGETS:
      memcpy((struct termios_t *) arg, &tty->termios, sizeof(struct termios_t));
      break;
    case TCSETS:
      memcpy(&tty->termios, (struct termios_t *) arg, sizeof(struct termios_t));
      break;
    case TCSETSW:
      memcpy(&tty->termios, (struct termios_t *) arg, sizeof(struct termios_t));
      break;
    case TCSETSF:
      memcpy(&tty->termios, (struct termios_t *) arg, sizeof(struct termios_t));
      break;
    case TIOCGWINSZ:
      memcpy((struct winsize_t *) arg, &tty->winsize, sizeof(struct winsize_t));
      break;
    case TIOCGPGRP:
      *((pid_t *) arg) = tty->pgrp;
      break;
    case TIOCSPGRP:
      tty->pgrp = *((pid_t *) arg);
      break;
    default:
      printf("Unknown ioctl request (%x) on device %x\n", request, dev);
      break;
  }

  return 0;
}

/*
 * Poll a tty.
 */
int tty_poll(dev_t dev)
{
  struct tty_t *tty;
  int mask = 0;

  /* get tty */
  tty = tty_lookup(dev);
  if (!tty)
    return -EINVAL;

  /* set waiting channel */
  current_task->waiting_chan = tty;

  /* check if there is some characters to read */
  if (tty->w_pos > tty->r_pos)
    mask |= POLLIN;

  return mask;
}

/*
 * Signal foreground processes group.
 */
void tty_signal_group(dev_t dev, int sig)
{
  struct tty_t *tty;

  /* get tty */
  tty = tty_lookup(dev);
  if (!tty)
    return;

  /* send signal */
  task_signal_group(tty->pgrp, sig);
}

/*
 * TTY update.
 */
static void tty_refresh()
{
  /* update current screen */
  if (tty_table[current_tty].fb.dirty)
    tty_table[current_tty].fb.update(&tty_table[current_tty].fb);

  /* reschedule timer */
  timer_event_mod(&refresh_tm, jiffies + ms_to_jiffies(TTY_DELAY_UPDATE_MS));
}

/*
 * Init TTYs.
 */
int init_tty(struct multiboot_tag_framebuffer *tag_fb)
{
  int i;

  /* init each tty */
  for (i = 0; i < NB_TTYS; i++) {
    tty_table[i].dev = DEV_TTY1 + i;
    tty_table[i].pgrp = 0;
    tty_table[i].r_pos = 0;
    tty_table[i].w_pos = 0;
    tty_table[i].buf[0] = 0;
    tty_table[i].write = console_write;

    /* init frame buffer */
    init_framebuffer(&tty_table[i].fb, tag_fb);

    /* set winsize */
    tty_table[i].winsize.ws_row = tty_table[i].fb.height;
    tty_table[i].winsize.ws_col = tty_table[i].fb.width;
    tty_table[i].winsize.ws_xpixel = 0;
    tty_table[i].winsize.ws_ypixel = 0;

    /* init termios */
    tty_table[i].termios = (struct termios_t) {
      .c_iflag    = ICRNL,
      .c_oflag    = OPOST | ONLCR,
      .c_cflag    = 0,
      .c_lflag    = IXON | ISIG | ICANON | ECHO | ECHOCTL | ECHOKE,
      .c_line     = 0,
      .c_cc       = INIT_C_CC,
    };
  }

  /* set current tty to first tty */
  current_tty = 0;

  /* create refresh timer */
  timer_event_init(&refresh_tm, tty_refresh, NULL, jiffies + ms_to_jiffies(TTY_DELAY_UPDATE_MS));
  timer_event_add(&refresh_tm);

  return 0;
}
