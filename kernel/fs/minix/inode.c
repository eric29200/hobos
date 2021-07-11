#include <fs/minix_fs.h>
#include <proc/sched.h>
#include <mm/mm.h>
#include <drivers/tty.h>
#include <stdio.h>
#include <stderr.h>
#include <fcntl.h>
#include <string.h>

/*
 * Directory operations.
 */
struct file_operations_t minix_dir_fops = {
  .read           = minix_file_read,
  .write          = minix_file_write,
  .getdents64     = minix_getdents64,
};

/*
 * File operations.
 */
struct file_operations_t minix_file_fops = {
  .read           = minix_file_read,
  .write          = minix_file_write,
};

/*
 * Minix file inode operations.
 */
struct inode_operations_t minix_file_iops = {
  .fops           = &minix_file_fops,
  .follow_link    = minix_follow_link,
  .readlink       = minix_readlink,
  .truncate       = minix_truncate,
};

/*
 * Minix directory inode operations.
 */
struct inode_operations_t minix_dir_iops = {
  .fops           = &minix_dir_fops,
  .lookup         = minix_lookup,
  .create         = minix_create,
  .link           = minix_link,
  .unlink         = minix_unlink,
  .symlink        = minix_symlink,
  .mkdir          = minix_mkdir,
  .rmdir          = minix_rmdir,
  .rename         = minix_rename,
  .mknod          = minix_mknod,
  .truncate       = minix_truncate,
};

/*
 * Read an inode.
 */
int minix_read_inode(struct inode_t *inode)
{
  struct minix_inode_t *minix_inode;
  struct buffer_head_t *bh;
  uint32_t block, i, j;

  if (!inode)
    return -EINVAL;

  /* read minix inode block */
  block = 2 + inode->i_sb->s_imap_blocks + inode->i_sb->s_zmap_blocks + (inode->i_ino - 1) / MINIX_INODES_PER_BLOCK;
  bh = bread(inode->i_sb->s_dev, block);
  if (!bh) {
    iput(inode);
    return -EIO;
  }

  /* read minix inode */
  minix_inode = (struct minix_inode_t *) bh->b_data;
  i = (inode->i_ino - 1) % MINIX_INODES_PER_BLOCK;

  /* fill in memory inode */
  inode->i_mode = minix_inode[i].i_mode;
  inode->i_uid = minix_inode[i].i_uid;
  inode->i_size = minix_inode[i].i_size;
  inode->i_time = minix_inode[i].i_atime;
  inode->i_gid = minix_inode[i].i_gid;
  inode->i_nlinks = minix_inode[i].i_nlinks;
  for (j = 0; j < 10; j++)
    inode->i_zone[j] = minix_inode[i].i_zone[j];

  if (S_ISDIR(inode->i_mode))
    inode->i_op = &minix_dir_iops;
  else if (S_ISCHR(inode->i_mode))
    inode->i_op = char_get_driver(inode);
  else
    inode->i_op = &minix_file_iops;

  /* free minix inode */
  brelse(bh);

  return 0;
}

/*
 * Write an inode on disk.
 */
int minix_write_inode(struct inode_t *inode)
{
  struct minix_inode_t *minix_inode;
  struct buffer_head_t *bh;
  uint32_t block, i, j;

  if (!inode)
    return -EINVAL;

  /* read minix inode block */
  block = 2 + inode->i_sb->s_imap_blocks + inode->i_sb->s_zmap_blocks + (inode->i_ino - 1) / MINIX_INODES_PER_BLOCK;
  bh = bread(inode->i_sb->s_dev, block);
  if (!bh)
    return -EIO;

  /* read minix inode */
  minix_inode = (struct minix_inode_t *) bh->b_data;
  i = (inode->i_ino - 1) % MINIX_INODES_PER_BLOCK;

  /* fill in on disk inode */
  minix_inode[i].i_mode = inode->i_mode;
  minix_inode[i].i_uid = inode->i_uid;
  minix_inode[i].i_size = inode->i_size;
  minix_inode[i].i_atime = inode->i_time;
  minix_inode[i].i_mtime = inode->i_time;
  minix_inode[i].i_ctime = inode->i_time;
  minix_inode[i].i_gid = inode->i_gid;
  minix_inode[i].i_nlinks = inode->i_nlinks;
  for (j = 0; j < 10; j++)
    minix_inode[i].i_zone[j] = inode->i_zone[j];

  /* write inode block */
  bh->b_dirt = 1;
  brelse(bh);

  return 0;
}

/*
 * Put an inode.
 */
int minix_put_inode(struct inode_t *inode)
{
  /* check inode */
  if (!inode)
    return -EINVAL;

  /* truncate and free inode */
  if (!inode->i_nlinks) {
    minix_truncate(inode);
    minix_free_inode(inode);
  }

  return 0;
}

/*
 * Get an inode buffer.
 */
static struct buffer_head_t *inode_getblk(struct inode_t *inode, int nr, int create)
{
  /* create block if needed */
  if (create && !inode->i_zone[nr])
    if ((inode->i_zone[nr] = minix_new_block(inode->i_sb)))
      inode->i_dirt = 1;

  if (!inode->i_zone[nr])
    return NULL;

  /* read block from device */
  return bread(inode->i_dev, inode->i_zone[nr]);
}

/*
 * Get a block buffer.
 */
static struct buffer_head_t *block_getblk(struct inode_t *inode, struct buffer_head_t *bh, int block, int create)
{
  int i;

  if (!bh)
    return NULL;

  /* create block if needed */
  i = ((uint32_t *) bh->b_data)[block];
  if (create && !i) {
    if ((i = minix_new_block(inode->i_sb))) {
      ((uint32_t *) (bh->b_data))[block] = i;
      bh->b_dirt = 1;
    }
  }

  /* release block */
  brelse(bh);

  if (!i)
    return NULL;

  /* read block from device */
  return bread(inode->i_dev, i);
}

/*
 * Read a buffer.
 */
struct buffer_head_t *minix_bread(struct inode_t *inode, int block, int create)
{
  struct buffer_head_t *bh;

  /* check block number */
  if (block < 0 || (uint32_t) block >= inode->i_sb->s_max_size / BLOCK_SIZE)
    return NULL;

  /* direct block */
  if (block < 7)
    return inode_getblk(inode, block, create);

  /* indirect block */
  block -= 7;
  if (block < 256) {
    bh = inode_getblk(inode, 7, create);
    return block_getblk(inode, bh, block, create);
  }

  /* double indirect block */
  block -= 256;
  if (block < 256 * 256) {
    bh = inode_getblk(inode, 8, create);
    bh = block_getblk(inode, bh, (block >> 8) & 255, create);
    return block_getblk(inode, bh, block & 255, create);
  }

  /* triple indirect block */
  block -= 256 * 256;
  bh = inode_getblk(inode, 9, create);
  bh = block_getblk(inode, bh, (block >> 16) & 255, create);
  bh = block_getblk(inode, bh, (block >> 8) & 255, create);
  return block_getblk(inode, bh, block & 255, create);
}
