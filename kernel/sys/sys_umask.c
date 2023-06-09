#include <sys/syscall.h>

/*
 * Umask system call.
 */
mode_t sys_umask(mode_t mask)
{
	mode_t ret = current_task->fs->umask;
	current_task->fs->umask = mask & 0777;
	return ret;
}
