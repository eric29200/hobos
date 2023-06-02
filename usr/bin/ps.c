#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <dirent.h>
#include <limits.h>

#include "../libutils/libutils.h"

/*
 * Process.
 */
struct process {
	pid_t		pid;		/* process id */
	uid_t		uid;		/* user id */
	char *		name;		/* process name */
};

/* processes list */
static struct process *processes = NULL;
static size_t processes_size = 0;
static size_t processes_capacity = 0;

/* formats */
size_t max_name_len = 0;
static char format_name[32];
size_t max_pid_len = 0;
static char format_pid[32];
size_t max_uid_len = 0;
static char format_uid[32];

/*
 * Get an empty process.
 */
struct process *process_get_empty()
{
	/* grow processes array if needed */
	if (processes_size >= processes_capacity) {
		processes_capacity += 64;
		processes = (struct process *) realloc(processes, sizeof(struct process) * processes_capacity);
		if (!processes) {
			perror("realloc");
			exit(1);
		}
	}

	/* get next process */
	memset(&processes[processes_size], 0, sizeof(struct process));
	return &processes[processes_size++];
}

/*
 * Add a process.
 */
static int process_add(struct dirent *entry)
{
	char path[PATH_MAX], *line = NULL;
	struct process *p;
	FILE *fp = NULL;
	size_t n = 0;
	ssize_t len;
	pid_t pid;

	if (!entry)
		return 1;

	/* parse pid */
	pid = atoi(entry->d_name);
	if (!pid)
		goto err;
	
	/* open status file */
	snprintf(path, PATH_MAX, "/proc/%d/status", pid);
	fp = fopen(path, "r");
	if (!fp) {
		perror(path);
		goto err;
	}

	/* get an empty process */
	p = process_get_empty();
	if (!p)
		goto err;

	/* get process informations */
	while ((len = getline(&line, &n, fp)) > 0) {
		/* remove ending \n */
		if (line[len - 1] == '\n')
			line[len - 1] = 0;

		/* collect informations */
		if (len > 6 && strncmp(line, "Name:\t", 6) == 0)
			p->name = strdup(line + 6);
		else if (len > 5 && strncmp(line, "Pid:\t", 5) == 0)
			p->pid = atoi(line + 5);
		else if (len > 5 && strncmp(line, "Uid:\t", 5) == 0)
			p->uid = atoi(line + 5);
	}

	/* close status file */
	free(line);
	fclose(fp);

	return 0;
err:
	if (fp)
		fclose(fp);
	if (line)
		free(line);
	return -1;
}

/*
 * Set format.
 */
static void ps_set_format()
{
	struct process *p;
	char buf[BUFSIZ];
	size_t len, i;

	/* get maximum lengths */
	for (i = 0; i < processes_size; i++) {
		p = &processes[i];

		len = strlen(p->name);
		if (len > max_name_len)
			len = max_name_len;

		len = snprintf(buf, BUFSIZ, "%d", p->pid);
		if (len > max_pid_len)
			max_pid_len = len;

		len = snprintf(buf, BUFSIZ, "%d", p->uid);
		if (len > max_uid_len)
			max_uid_len = len;
	}
	 
	/* set formats */
	sprintf(format_name, "%%-%d.%ds      ", max_name_len, max_name_len);
	sprintf(format_pid, "%%%dd      ", max_pid_len);
	sprintf(format_uid, "%%%dd      ", max_uid_len);
}

/*
 * Print processes.
 */
static int ps()
{
	struct dirent *entry;
	DIR *dirp;
	size_t i;

	/* open /proc */
	dirp = opendir("/proc");
	if (!dirp) {
		perror("/proc");
		return -1;
	}

	/* add all processes */
	while ((entry = readdir(dirp)) != NULL)
		process_add(entry);

	/* close /proc */
	closedir(dirp);

	/* set format */
	ps_set_format();

	/* print header */
	printf("USER");
	for (i = 0; i < max_uid_len + 6 - 4; i++)
		printf(" ");
	printf("PID");
	for (i = 0; i < max_pid_len + 6 - 3; i++)
		printf(" ");
	printf("NAME\n");

	/* print all processes */
	for (i = 0; i < processes_size; i++) {
		printf(format_uid, processes[i].uid);
		printf(format_pid, processes[i].pid);
		printf(format_name, processes[i].name);
		printf("\n");
	}

	return 0;
}

/*
 * Usage.
 */
static void usage(const char *name)
{
	fprintf(stderr, "Usage: %s\n", name);
	fprintf(stderr, "    , --help        print help and exit\n");
}
 
/* options */
struct option long_opts[] = {
	{ "help",	no_argument,	0,	OPT_HELP	},
	{ 0,		0,		0,	0		},
};

int main(int argc, char **argv)
{
	const char *name = argv[0];
	int c;

	/* get options */
	while ((c = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
		switch (c) {
			case OPT_HELP:
				usage(name);
				exit(0);
				break;
			default:
				exit(1);
				break;
		}
	}

	/* skip options */
	argc -= optind;
	argv += optind;

	/* print processes */
	return ps();
}