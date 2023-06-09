#include <sys/syscall.h>
#include <proc/sched.h>
#include <fs/fs.h>
#include <fcntl.h>
#include <stderr.h>

/*
 * Change directory system call.
 */
int sys_chdir(const char *path)
{
	struct inode_t *inode;

	/* get inode */
	inode = namei(AT_FDCWD, NULL, path, 1);
	if (!inode)
		return -ENOENT;

	/* check directory */
	if (!S_ISDIR(inode->i_mode)) {
		iput(inode);
		return -ENOTDIR;
	}

	/* release current working dir */
	iput(current_task->fs->cwd);

	/* set current working dir */
	current_task->fs->cwd = inode;

	return 0;
}
