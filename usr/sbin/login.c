#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <pwd.h>

#include "../libreadline/readline.h"

/*
 * Login as user.
 */
static void login(struct passwd *pwd)
{
	char sh_name[PATH_MAX];

	/* change group */
	if (setgid(pwd->pw_gid) < 0) {
		perror("setgid");
		exit(1);
	}

	/* change user */
	if (setuid(pwd->pw_uid) < 0) {
		perror("setuid");
		exit(1);
	}

	/* go to home directory */
	if (chdir(pwd->pw_dir) < 0) {
		printf("No home directory. Starting in /\n");
		fflush(stdout);
		chdir("/");
	}

	/* set environ */
	setenv("USER", pwd->pw_name, 1);
	setenv("HOME", pwd->pw_dir, 1);
	setenv("SHELL", pwd->pw_shell, 1);

	/* get shell name */
	*sh_name = '-';
	strncpy(sh_name + 1, pwd->pw_shell, PATH_MAX - 1);

	/* execute shell */
	execl(pwd->pw_shell, sh_name, NULL);

	/* execl failed */
	perror(pwd->pw_shell);
	exit(1);
}

int main()
{
	char *login_str = NULL;
	struct rline_ctx ctx;
	struct passwd *pwd;

	/* init readline context */
	rline_init_ctx(&ctx, 0);

	for (;;) {
		/* print prompt */
		printf("\nlogin: ");
		fflush(stdout);

		/* read user */
		if (rline_readline(&ctx, &login_str) <= 0)
			continue;

		/* get user informations */
		pwd = getpwnam(login_str);
		if (!pwd) {
			printf("Login incorrect\n");
			fflush(stdout);
			continue;
		}

		/* login */
		printf("\n");
		login(pwd);
	}

	/* free login */
	if (login_str)
		free(login_str);

	/* exit readline context */
	rline_exit_ctx(&ctx);

	return 0;
}