#include <fs/minix_fs.h>
#include <proc/sched.h>
#include <mm/mm.h>
#include <string.h>
#include <stdio.h>
#include <stderr.h>

/*
 * Get first free bit in a bitmap block (inode or block).
 */
static int minix_get_free_bitmap(struct buffer_head_t *bh)
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
static void minix_set_bitmap(struct buffer_head_t *bh, int i)
{
  bh->b_data[i / 8] |= (0x1 << (i % 8));
}

/*
 * Clear bit in a bitmap block (inode or block).
 */
static void minix_clear_bitmap(struct buffer_head_t *bh, int i)
{
  bh->b_data[i / 8] &= ~(0x1 << (i % 8));
}

/*
 * Create a new block.
 */
uint32_t minix_new_block(struct super_block_t *sb)
{
  struct buffer_head_t *bh;
  uint32_t block_nr, i;
  int j;

  /* find first free block in bitmap */
  for (i = 0; i < sb->s_zmap_blocks; i++) {
    j = minix_get_free_bitmap(sb->s_zmap[i]);
    if (j != -1)
      break;
  }

  /* no free block */
  if (j == -1)
    return 0;

  /* compute real block number */
  block_nr = j + i * BLOCK_SIZE * 8 + sb->s_firstdatazone - 1;
  if (block_nr >= sb->s_nzones)
    return 0;

  /* read new block */
  bh = bread(sb->s_dev, block_nr);
  if (!bh)
    return 0;

  /* zero new block */
  memset(bh->b_data, 0, BLOCK_SIZE);
  brelse(bh);

  /* set block in bitmap and write bitmap to disk */
  minix_set_bitmap(sb->s_zmap[i], j);
  if (bwrite(sb->s_zmap[i]) != 0)
    return 0;

  return block_nr;
}

/*
 * Free a block.
 */
int minix_free_block(struct super_block_t *sb, uint32_t block)
{
  struct buffer_head_t *bh;

  /* check block number */
  if (block < sb->s_firstdatazone || block >= sb->s_nzones)
    return -EINVAL;

  /* update/clear inode bitmap */
  bh = sb->s_zmap[block / (BLOCK_SIZE * 8)];
  minix_clear_bitmap(bh, block & (BLOCK_SIZE * 8 - 1));
  return bwrite(bh);
}

/*
 * Free an inode.
 */
int minix_free_inode(struct inode_t *inode)
{
  struct buffer_head_t *bh;
  int ret;

  if (!inode)
    return 0;

  /* panic if inode is still used */
  if (inode->i_ref > 1) {
    printf("Trying to free inode %d with ref=%d\n", inode->i_ino, inode->i_ref);
    panic("");
  }

  /* update/clear inode bitmap */
  bh = inode->i_sb->s_imap[inode->i_ino >> 13];
  minix_clear_bitmap(bh, inode->i_ino & (BLOCK_SIZE * 8 - 1));
  ret = bwrite(bh);

  /* free inode */
  memset(inode, 0, sizeof(struct inode_t));
  return ret;
}

/*
 * Create a new inode.
 */
struct inode_t *minix_new_inode(struct super_block_t *sb)
{
  struct inode_t *inode;
  uint32_t i;
  int j;

  /* get an empty new inode */
  inode = get_empty_inode();
  if (!inode)
    return NULL;

  /* find first free inode in bitmap */
  for (i = 0; i < sb->s_imap_blocks; i++) {
    j = minix_get_free_bitmap(sb->s_imap[i]);
    if (j != -1)
      break;
  }

  /* no free inode */
  if (j == -1)
    iput(inode);

  /* set inode */
  memset(inode, 0, sizeof(struct inode_t));
  inode->i_time = CURRENT_TIME;
  inode->i_nlinks = 1;
  inode->i_ino = i * BLOCK_SIZE * 8 + j;
  inode->i_ref = 1;
  inode->i_sb = sb;
  inode->i_dev = sb->s_dev;

  /* set inode in bitmap and write bitmap to disk */
  minix_set_bitmap(sb->s_imap[i], j);
  if (bwrite(sb->s_imap[i]) != 0) {
    minix_free_inode(inode);
    return NULL;
  }

  return inode;
}
