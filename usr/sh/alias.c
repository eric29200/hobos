#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>

#include "alias.h"
#include "utils.h"

#define ALIAS_TABLE_GROW_SIZE		16

/* alias table */
static size_t alias_table_capacity = 0;
struct alias **alias_table = NULL;
size_t nr_alias = 0;

/*
 * Free an alias.
 */
static void alias_free(struct alias *alias)
{
	if (alias) {
		if (alias->name)
			free(alias->name);

		if (alias->value)
			free(alias->value);
	}
}

/*
 * Create an alias.
 */
static struct alias *alias_create(const char *name, char *value)
{
	struct alias *alias;

	/* allocate a new alias */
	alias = (struct alias *) malloc(sizeof(struct alias));
	if (!alias)
		return NULL;

	/* reset alias */
	memset(alias, 0, sizeof(struct alias));

	/* set name */
	alias->name = strdup(name);
	if (!alias->name) {
		alias_free(alias);
		return NULL;
	}

	/* set value */
	alias->value = value;

	return alias;
}

/*
 * Add an alias.
 */
int alias_add(const char *name, char *value)
{
	struct alias *alias;

	/* remove old alias */
	alias_remove(name);

	/* grow alias table if needed */
	if (nr_alias + 1 >= alias_table_capacity) {
		alias_table_capacity += ALIAS_TABLE_GROW_SIZE;
		alias_table = (struct alias **) realloc(alias_table, sizeof(struct alias *) * alias_table_capacity);
		if (!alias_table)
			return -1;
	}

	/* create new alias */
	alias = alias_create(name, value);
	if (!alias)
		return -1;

	/* add alias */
	alias_table[nr_alias++] = alias;

	return 0;
}

/*
 * Remove an alias.
 */
bool alias_remove(const char *name)
{
	size_t i;

	/* find alias and free it */
	for (i = 0; i < nr_alias; i++) {
		if (strcmp(alias_table[i]->name, name) == 0) {
			alias_free(alias_table[i]);
			break;
		}
	}

	/* no matching alias */
	if (i >= nr_alias)
		return false;

	/* shift remaining aliases */
	for (; i < nr_alias - 1; i++)
		alias_table[i] = alias_table[i + 1];

	/* update number of aliases */
	nr_alias--;

	return true;
}

/*
 * Find an alias.
 */
struct alias *alias_find(const char *name)
{
	size_t i;

	for (i = 0; i < nr_alias; i++)
		if (strcmp(alias_table[i]->name, name) == 0)
			return alias_table[i];

	return NULL;
}