#include <string.h>

char *strstr(const char *haystack, const char *needle)
{
	size_t needle_len, len;

	/* empty needle */
	needle_len = strlen(needle);
	if (!needle_len)
		return (char *) haystack;

	for (;;) {
		/* find first character */
		haystack = strchr(haystack, *needle);
		if (!haystack || needle_len == 1)
			return (char *) haystack;

		/* remaining haystack too short */
		len = strlen(haystack);
		if (len < needle_len)
			return NULL;

		/* match */
		if (memcmp(haystack + 1, needle + 1, needle_len - 1) == 0)
			return (char *) haystack;

		/* go to next character */
		haystack++;
	}
}