#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <mntent.h>
#include <stdbool.h>
#include <sys/statfs.h>

#include "../libutils/libutils.h"

/*
 * Mount entry.
 */
struct mount_entry {
	char *			fs_name;		/* file system name */
	char *			dir_name;		/* directory name */
	struct statfs		sf;			/* file system stats */
	struct mount_entry *	next;			/* next mount entry */
};

static char *cols_header[6] = { "Filesystem", "Size", "Used", "Avail", "Use%", "Mounted on" };

/* columns width */
static size_t cols_width[5] = { 0 };

/*
 * Create a new mount entry.
 */
static struct mount_entry *create_mount_entry(struct mntent *mnt)
{
	struct mount_entry *entry = NULL;

	if (!mnt || !mnt->mnt_fsname || !mnt->mnt_dir)
		return NULL;

	/* allocate a new mount entry */
	entry = (struct mount_entry *) malloc(sizeof(struct mount_entry));
	if (!entry)
		goto err;
	
	/* set entry */
	memset(entry, 0, sizeof(struct mount_entry));

	/* set file system name  */
	entry->fs_name = strdup(mnt->mnt_fsname);
	if (!entry->fs_name)
		goto err;

	/* set directory name */
	entry->dir_name = strdup(mnt->mnt_dir);
	if (!entry->fs_name)
		goto err;

	/* stat file system */
	if (statfs(entry->dir_name, &entry->sf) < 0) {
		perror(entry->dir_name);
		goto err;
	}

	return entry;
err:
	if (entry) {
		if (entry->fs_name)
			free(entry->fs_name);
		if (entry->dir_name)
			free(entry->dir_name);
	}
	return NULL;
}

/*
 * Get mount entries.
 */
static struct mount_entry *get_mount_entries()
{
	struct mount_entry *head = NULL, *entry;
	struct mntent *mnt;
	FILE *fp;

	/* open /proc/mounts */
	fp = setmntent("/proc/mounts", "r");
	if (!fp) {
		perror("/proc/mounts");
		return NULL;
	}

	/* parse alle entries */
	for (;;) {
		/* get next entry */
		mnt = getmntent(fp);
		if (!mnt)
			break;
	
		/* create mount entry */
		entry = create_mount_entry(mnt);
		if (!entry)
			continue;

		/* add entry */
		entry->next = head;
		head = entry;
	}

	/* close /proc/mounts */
	endmntent(fp);

	return head;
}

/*
 * Measure columns width.
 */
static void measure_columns_width(char **cols)
{
	size_t len;
	int i;

	for (i = 0; i < 5; i++) {
		len = strlen(cols[i]);
		if (len + 4 > cols_width[i])
			cols_width[i] = len + 4;
	}
}

/*
 * Print columns.
 */
static void print_columns(char **cols)
{
	char fmt[16];
	size_t i;

	/* print file system name */
	i = printf("%s", cols[0]);
	for (; i < cols_width[0]; i++)
		printf(" ");

	/* print values */
	for (i = 1; i < 5; i++) {
		sprintf(fmt, "%%%d.%ds", cols_width[i], cols_width[i]);
		printf(fmt, cols[i]);
	}

	/* print mount point */
	printf("    %s", cols[5]);
	printf("\n");
}

/*
 * Show a mount entry.
 */
static void show_entry(struct mount_entry *entry, bool measuring)
{
	fsblkcnt_t blocks, used, avail, prct_used = 0;
	char *cols[6], buf[BUFSIZ];

	/* get values */
	blocks = entry->sf.f_blocks;
	used = entry->sf.f_blocks - entry->sf.f_bfree;
	avail = entry->sf.f_bavail;
	
	/* compute used % */
	if (used + avail)
		prct_used = used * 100 / (used + avail);

	/* print values in columns */
	cols[0] = entry->fs_name;
	cols[1] = buf;
	cols[2] = cols[1] + sprintf(cols[1], "%llu", blocks) + 1;
	cols[3] = cols[2] + sprintf(cols[2], "%llu", used) + 1;
	cols[4] = cols[3] + sprintf(cols[3], "%llu", avail) + 1;
	sprintf(cols[4], "%llu%", prct_used);
	cols[5] = entry->dir_name;

	/* measure or print columns */
	if (measuring)
		measure_columns_width(cols);
	else
		print_columns(cols);
}

/*
 * Get filesystems informations.
 */
static int df()
{
	struct mount_entry *entries, *entry;
	int i;

	/* init columns width */
	for (i = 0; i < 5; i++)
		cols_width[i] = strlen(cols_header[i]);

	/* get entries */
	entries = get_mount_entries();

	/* measure entries */
	for (entry = entries; entry != NULL; entry = entry->next)
		show_entry(entry, true);

	/* print header */
	print_columns(cols_header);
	
	/* print entries */
	for (entry = entries; entry != NULL; entry = entry->next)
		show_entry(entry, false);

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

	return df();
}
