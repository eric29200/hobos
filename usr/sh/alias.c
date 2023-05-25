#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alias.h"
#include "utils.h"

#define ALIAS_TABLE_GROW_SIZE		16

/* alias table */
static struct alias *alias_table = NULL;
static size_t alias_table_capacity = 0;
static size_t nr_alias = 0;

/*
 * Add an alias.
 */
static int alias_add(const char *name, char *value)
{
	struct alias *alias;

	/* replace old alias */
	alias = alias_find(name);
	if (alias) {
		free(alias->value);
		alias->value = value;
		return 0;
	}

	/* grow alias table if needed */
	if (nr_alias + 1 >= alias_table_capacity) {
		alias_table_capacity += ALIAS_TABLE_GROW_SIZE;
		alias_table = (struct alias *) realloc(alias_table, sizeof(struct alias) * alias_table_capacity);
		if (!alias_table)
			return -1;
	}

	/* set alias name */
	alias_table[nr_alias].name = strdup(name);
	if (!alias_table[nr_alias].name)
		return -1;

	/* set alias value */
	alias_table[nr_alias++].value = value;

	return 0;
}

/*
 * Find an alias.
 */
struct alias *alias_find(const char *name)
{
	size_t i;

	for (i = 0; i < nr_alias; i++)
		if (strcmp(alias_table[i].name, name) == 0)
			return &alias_table[i];

	return NULL;
}

/*
 * Do alias command.
 */
int cmd_alias(int argc, char **argv)
{
	struct alias *alias;
	char *name, *value;
	size_t i;

	/* print all aliases */
	if (argc < 2) {
		for (i = 0; i < nr_alias; i++)
			printf("%s\t%s\n", alias_table[i].name, alias_table[i].value);

		return 0;
	}

	/* get alias name */
	name = argv[1];

	/* print one alias */
	if (argc == 2) {
		alias = alias_find(name);
		if (alias)
			printf("%s\n", alias->value);

		return 0;
	}

	/* alias alias forbidden */
	if (strcmp(name, "alias") == 0) {
		fprintf(stderr, "Cannot alias \"alias\"\n");
		return -1;
	}

	/* concat arguments */
	value = concat_args(argc - 2, argv + 2);
	if (!value)
		return -1;

	/* add alias */
	return alias_add(name, value);
}
