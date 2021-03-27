#include "../include/screen.h"
#include "../include/io.h"

static unsigned short *video_memory = (unsigned short *) VIDEO_MEMORY;
static unsigned char cursor_x = 0;
static unsigned char cursor_y = 0;

/*
 * Move the cursor.
 */
static void move_cursor()
{
  unsigned short cursor_offset = cursor_y * NB_COLS + cursor_x;

  outb(REG_SCREEN_CTRL, 14);
  outb(REG_SCREEN_DATA, cursor_offset >> 8);
  outb(REG_SCREEN_CTRL, 15);
  outb(REG_SCREEN_DATA, cursor_offset);
}

/*
 * Clear the screen.
 */
void screen_clear()
{
  int i;

  /* blank all screen */
  for (i = 0; i < NB_ROWS * NB_COLS; i++)
    video_memory[i] = ' ';

  /* reset cursor */
  cursor_x = 0;
  cursor_y = 0;
  move_cursor();
}

/*
 * Scroll the screen up by one line.
 */
static void screen_scroll()
{
  int i;

  if(cursor_y >= NB_ROWS) {
    /* copy lines to upper ones */
    for (i = 0; i < (NB_ROWS - 1) * NB_COLS; i++)
      video_memory[i] = video_memory[i + NB_COLS];

    /* blank last line */
    for (i = (NB_ROWS - 1) * NB_COLS; i < NB_ROWS * NB_COLS; i++)
      video_memory[i] = ' ';

    cursor_y = NB_ROWS - 1;
  }
}

/*
 * Write a character to the screen.
 */
void screen_putc(char c)
{
  unsigned char *location;

  /* handle special characters */
  if (c == BACKSPACE_KEY && cursor_x) {
    cursor_x--;
  } else if (c == TAB_KEY) {
    cursor_x = (cursor_x + TAB_SIZE) & ~(TAB_SIZE - 1);
  } else if (c == '\r') {
    cursor_x = 0;
  } else if (c == '\n') {
    cursor_x = 0;
    cursor_y++;
  } else if(c >= ' ') {
    location = (unsigned char *) (video_memory + (cursor_y * NB_COLS + cursor_x));
    location[0] = c;
    location[1] = WHITE_ON_BLACK;
    cursor_x++;
  }

  /* insert a new line */
  if (cursor_x >= NB_COLS) {
    cursor_x = 0;
    cursor_y++;
  }

  /* scroll if needed */
  screen_scroll();

  /* update cursor */
  move_cursor();
}

/*
 * Write a message to the screen.
 */
void screen_puts(const char *s)
{
  int i;

  for (i = 0; s[i] != 0; i++)
    screen_putc(s[i]);
}

/*
 * Write an integer to the screen.
 */
void screen_puti(int n)
{
  int i, j, acc;
  char c[32];
  char c2[32];

  if (n == 0) {
    screen_putc('0');
    return;
  }

  i = 0;
  acc = n;
  while (acc > 0) {
    c[i] = '0' + acc % 10;
    acc /= 10;
    i++;
  }
  c[i] = 0;

  c2[i--] = 0;
  j = 0;
  while (i >= 0)
    c2[i--] = c[j++];

  screen_puts(c2);
}
