#include <mntent.h>
#include <string.h>
#include <errno.h>

static char *buf;
static size_t bufsize;
static struct mntent mnt;

struct mntent *getmntent(FILE *stream)
{
	char *s;

	for (;;) {
		/* get next line */
		getline(&buf, &bufsize, stream);

		/* eof */
		if (feof(stream) || ferror(stream))
			return NULL;

		/* check end of line */
		if (!strchr(buf, '\n')) {
			errno = ERANGE;
			return NULL;
		}

		/* skip comments */
		s = strtok(buf, " ");
		if (!s || !*s || *s == '#')
			continue;

		/* parse entry */
		mnt.mnt_fsname = s;
		mnt.mnt_dir = strtok(NULL, " ");
		mnt.mnt_type = strtok(NULL, " ");
		mnt.mnt_ops = strtok(NULL, " ");
		break;
	}

	return &mnt;
}

FILE *setmntent(const char *filename, const char *type)
{
	return fopen(filename, type);
}

int endmntent(FILE *stream)
{
	if (stream)
		fclose(stream);

	return 1;
}