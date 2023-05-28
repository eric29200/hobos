#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#define RC_PATH		"/etc/rc.conf"
#define NTTYS		4

/*
 * Execute startup script rc.conf.
 */
static int exec_rc()
{
	pid_t pid, ret;

	/* create new process */
	pid = fork();
	if (pid < 0) {
		perror(RC_PATH);
		return 1;
	}

	/* child : execute rc.conf */
	if (pid == 0) {
		execl("/bin/sh", "sh", RC_PATH, NULL, NULL);
		exit(0);
	}

	/* wait for child */
	for (;;) {
		ret = waitpid(pid, NULL, 0);
		if (ret == pid)
			break;
		if (ret < 0) {
			perror("waitpid");
			return 1;
		}
	}

	return 0;
}

/*
 * Spwan a shell on tty.
 */
static pid_t spawn_login(int tty_num)
{
	char tty[32];
	pid_t pid;
	int fd;

	/* close fds */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	/* set tty */
	sprintf(tty, "/dev/tty%d", tty_num);

	/* create a new process */
	pid = fork();
	if (pid == 0) {
		/* open tty as stdin, stdout, stderr */
		fd = open(tty, O_RDWR, 0);
		dup(STDIN_FILENO);
		dup(STDIN_FILENO);

		/* create a new process group (identified by current pid = leader process) */
		pid = getpid();
		setpgid(pid, pid);

		/* mark tty attached to this group */
		tcsetpgrp(fd, pid);

		/* exec login */
		if (execl("/sbin/login", "login", NULL, NULL) == -1)
			exit(0);
	}

	return pid;
}

/*
 * Init process.
 */
int main(void)
{
	pid_t ttys_pid[NTTYS];
	pid_t pid;
	int i;

	/* go to root dir */
	chdir("/");

	/* execute startup script */
	exec_rc();

	/* spawn login on each tty */
	for (i = 0; i < NTTYS; i++)
		ttys_pid[i] = spawn_login(i + 1);

	/* destroy zombie tasks */
	for (;;) {
		pid = waitpid(-1, NULL, 0);

		/* if login exited, respawn it */
		for (i = 0; i < NTTYS; i++)
			if (pid == ttys_pid[i])
				ttys_pid[i] = spawn_login(i + 1);
	}

	return 0;
}
