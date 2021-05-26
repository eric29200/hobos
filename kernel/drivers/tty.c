#include <drivers/serial.h>
#include <drivers/termios.h>
#include <drivers/tty.h>
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
 * Read a character from a tty (block if no character available).
 */
static int tty_read_wait(dev_t dev, int block)
{
  struct tty_t *tty;
  int c = -1;

  /* get tty */
  tty = tty_lookup(dev);
  if (!tty)
    return -EINVAL;

  /* wait for character */
  while (tty->r_pos >= tty->w_pos && block) {
    tty->r_pos = 0;
    tty->w_pos = 0;
    task_sleep(tty);
  }

  /* get next character */
  if (tty->r_pos < tty->w_pos)
    c = tty->buf[tty->r_pos++];

  return c;
}

/*
 * Read TTY.
 */
size_t tty_read(dev_t dev, void *buf, size_t n)
{
  size_t count = 0;
  int key;

  while (count < n) {
    /* read next char */
    key = tty_read_wait(dev, 1);

    /* nothing to read */
    if (key <= 0)
      return -EAGAIN;

    /* store new character */
    if (key == '\b')
      ((unsigned char *) buf)[--count] = 0;
    else
      ((unsigned char *) buf)[count++] = key;

    /* new line : break */
    if (key == 10)
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

  /* get tty */
  tty = &tty_table[current_tty];

  /* adjust read/write positions */
  if (tty->w_pos >= TTY_BUF_SIZE)
    tty->w_pos = TTY_BUF_SIZE - 1;
  if (tty->r_pos > tty->w_pos)
    tty->r_pos = tty->w_pos = 0;

  /* handle special keys */
  if (c == 13)
    c = '\n';
  else if (c == 127)
    c = '\b';

  /* store character */
  tty->buf[tty->w_pos++] = c;

  /* wake up eventual process */
  task_wakeup(tty);

  /* echo character on device */
  tty_write(tty->dev, &c, 1);
}

/*
 * Write to TTY.
 */
size_t tty_write(dev_t dev, const void *buf, size_t n)
{
  struct tty_t *tty;

  /* get tty */
  tty = tty_lookup(dev);
  if (!tty)
    return -EINVAL;

  /* write to frame buffer */
  return fb_write(&tty->fb, buf, n);
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
    init_framebuffer(&tty_table[i].fb, tag_fb);
    tty_table[i].winsize.ws_row = tty_table[i].fb.height;
    tty_table[i].winsize.ws_col = tty_table[i].fb.width;
    tty_table[i].winsize.ws_xpixel = 0;
    tty_table[i].winsize.ws_ypixel = 0;
  }

  /* set current tty to first tty */
  current_tty = 0;

  /* create refrsh timer */
  timer_event_init(&refresh_tm, tty_refresh, NULL, jiffies + ms_to_jiffies(TTY_DELAY_UPDATE_MS));
  timer_event_add(&refresh_tm);

  return 0;
}
