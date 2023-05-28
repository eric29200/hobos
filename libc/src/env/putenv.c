#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "__env_impl.h"

static char **oldenv = NULL;

int __putenv(char *var, size_t namelen, char *r)
{
	char **e, **newenv, *tmp;
	size_t i = 0;

	/* replace in environ */
	if (environ) {
		for (e = environ; *e; e++, i++) {
			if (strncmp(var, *e, namelen + 1) == 0) {
				printf("biz\n");
				tmp = *e;
				*e = var;
				__env_rm_add(tmp, r);
				return 0;
			}
		}
	}

	/* grow old environ */
	newenv = realloc(oldenv, sizeof(char *) * (i + 2));
	if (!newenv)
		goto err;

	/* free old environ */
	if (oldenv) {
		/* copy environ */
		if (i)
			memcpy(newenv, environ, sizeof(char *) * i);

		/* free old environ */	
		free(oldenv);
	}

	/* put var */
	newenv[i] = var;
	newenv[i + 1] = 0;

	/* set environ */
	environ = oldenv = newenv;

	/* add variable in alloced environ */
	if (r)
		__env_rm_add(NULL, r);

	return 0;
err:
	if (r)
		free(r);

	return -1;
}

int putenv(char *string)
{
	size_t namelen = strchrnul(string, '=') - string;

	/* remove variable */
	if (!namelen || !string[namelen])
		return unsetenv(string);

	/* put variable */
	return __putenv(string, namelen, NULL);
}