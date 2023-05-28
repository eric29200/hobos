#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "__env_impl.h"

int unsetenv(const char *name)
{
	char **e, **eo;
	size_t len;

	/* check name */
	len = strchrnul(name, '=') - name;
	if (!len || name[len]) {
		errno = EINVAL;
		return -1;
	}

	if (environ) {
		/* remove matching variables and left shift variables */
		for (e = eo = environ; *e; e++)
			if (strncmp(name, *e, len) == 0 && (*e)[len] == '=')
				__env_rm_add(*e, NULL);
			else if (eo != e)
				*eo++ = *e;
			else
				eo++;

		/* end environ */
		if (eo != e)
			*eo = 0;
	}

	return 0;
}