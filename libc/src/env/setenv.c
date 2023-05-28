#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "__env_impl.h"

static char **environ_alloced = NULL;
static size_t environ_alloced_len = 0;

/*
 * Remove old variable and add new variable.
 */
void __env_rm_add(char *oldvar, char *newvar)
{
	char **tmp;
	size_t i;

	for (i = 0; i < environ_alloced_len; i++) {
		/* replace old with new */
		if (environ_alloced[i] == oldvar) {
			environ_alloced[i] = newvar;
			free(oldvar);
			return;
		}

		/* put new var at first free place */
		if (!environ_alloced[i] && newvar) {
			environ_alloced[i] = newvar;
			newvar = NULL;
		}
	}

	if (!newvar)
		return;

	/* grow alloced environ */
	tmp = realloc(environ_alloced, sizeof(char *) * (environ_alloced_len + 1));
	if (!tmp)
		return;

	/* add new variabe */
	environ_alloced = tmp;
	environ_alloced[environ_alloced_len++] = newvar;
}

int setenv(const char *name, const char *value, int overwrite)
{
	size_t namelen, valuelen;
	char *var;

	/* check name */
	if (!name || !(namelen = strchrnul(name, '=') - name) || name[namelen]) {
		errno = EINVAL;
		return -1;
	}

	/* variable already exists */
	if (!overwrite && getenv(name))
		return 0;

	/* allocate new variable */
	valuelen = strlen(value);
	var = malloc(namelen + valuelen + 2);
	if (!var) {
		errno = ENOMEM;
		return -1;
	}

	/* concat name and value */
	memcpy(var, name, namelen);
	var[namelen] = '=';
	memcpy(var + namelen + 1, value, valuelen + 1);

	/* put variable in env */
	return __putenv(var, namelen, var);
}