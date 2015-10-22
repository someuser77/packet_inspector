#ifndef _ASPRINTF_H_
#define _ASPRINTF_H_

#include <stdarg.h>

int vasprintf(char **ret, const char *fmt, va_list ap);
int asprintf(char **ret, const char *fmt, ...);

#endif
