#include <stdio.h>
#include <limits.h>

int vsprintf(char *str, const char *format, va_list ap)
{
	return vsnprintf(str, INT_MAX, format, ap);
}
