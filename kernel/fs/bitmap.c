#include <fs/fs.h>
#include <proc/sched.h>
#include <mm/mm.h>
#include <string.h>
#include <stdio.h>

/* root super block */
extern struct minix_super_block_t *root_sb;

/*
 * Get first free bit in a bitmap block (inode or block).
 */
static int get_free_bitmap(struct buffer_head_t *bh)
{
  int i, j;

  for (i = 0; i < BLOCK_SIZE; i++)
    for (j = 0; j < 8; j++)
      if (!(bh->b_data[i] & (0x1 << j)))
        return i * 8 + j;

  return -1;
}

/*
 * Set bit in a bitmap block (inode or block).
 */
static void set_bitmap(struct buffer_head_t *bh, int i)
{
  bh->b_data[i / 8] |= (0x1 << (i % 8));
}

/*
 * Clear bit in a bitmap block (inode or block).
 */
static void clear_bitmap(struct buffer_head_t *bh, int i)
{
  bh->b_data[i / 8] &= ~(0x1 << (i % 8));
}

/*
 * Free an inode.
 */
void free_inode(struct inode_t *inode)
{
  struct buffer_head_t *bh;

  if (!inode)
    return;

  /* panic if inode is still used */
  if (inode->i_ref > 1) {
    printf("Tring to free inode %d with count=%d\n", inode->i_ino, inode->i_ref);
    panic("");
  }

  /* update/clear inode bitmap */
  bh = root_sb->s_imap[inode->i_ino >> 13];
  clear_bitmap(bh, inode->i_ino & 8191);
  bwrite(bh);

  /* free inode */
  kfree(inode);
}

/*
 * Create a new inode.
 */
struct inode_t *new_inode()
{
  struct inode_t *inode;
  int i, j;

  /* allocate a new inode */
  inode = (struct inode_t *) kmalloc(sizeof(struct inode_t));
  if (!inode)
    return NULL;

  /* find first free inode in bitmap */
  for (i = 0; i < root_sb->s_imap_blocks; i++) {
    j = get_free_bitmap(root_sb->s_imap[i]);
    if (j != -1)
      break;
  }

  /* no free inode */
  if (j == -1)
    kfree(inode);

  /* set inode */
  memset(inode, 0, sizeof(struct inode_t));
  inode->i_time = CURRENT_TIME;
  inode->i_nlinks = 1;
  inode->i_ino = i * BLOCK_SIZE * 8 + j;
  inode->i_ref = 1;
  inode->i_sb = root_sb;
  inode->i_dev = root_sb->s_dev;

  /* set inode in bitmap and write bitmap to disk */
  set_bitmap(root_sb->s_imap[i], j);
  if (bwrite(root_sb->s_imap[i]) != 0) {
    free_inode(inode);
    return NULL;
  }

  return inode;
}
