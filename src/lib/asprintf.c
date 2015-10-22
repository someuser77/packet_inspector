#include <stdlib.h>
#include <stdio.h>
#include "asprintf.h"

int vasprintf(char **ret, const char *fmt, va_list ap) {
	
	int expected_length, actual_length;
	va_list ap_copy;
	va_copy(ap_copy, ap);
	
	expected_length = vsnprintf(NULL, 0, fmt, ap_copy); 
	if (expected_length < 0)
		goto error;
	
	*ret = (char *)malloc((sizeof(char) * expected_length) + 1);
	
	if (*ret == NULL) 
		goto error;
	
	actual_length = vsnprintf(*ret, expected_length + 1, fmt, ap);
	
	if (actual_length < 0 || actual_length > expected_length + 1) {
		free(*ret);
		goto error;
	}
	
	return actual_length;
	
error:
	*ret = NULL;
	return -1;
}

int asprintf(char **ret, const char *fmt, ...) {
	int len;
	va_list ap;
	
	va_start(ap, fmt);
	len = vasprintf(ret, fmt, ap);
	va_end(ap);
	return len;
}

