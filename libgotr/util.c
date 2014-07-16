#include <errno.h>
#include <gcrypt.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "util.h"


void gotr_eprintf(const char *format, ...)
{
	va_list ap;

	fputs("libgotr: ", stderr);

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);

	if (format[0] != '\0' && format[strlen(format)-1] == ':') {
		fputc(' ', stderr);
		perror(NULL);
	} else {
		fputc('\n', stderr);
	}
}

void gotr_assert_fail(const char *assertion, const char *file, unsigned int line, const char *function)
{
	gotr_eprintf("Assertion failed in file %s line %d function %s: %s", file, line, function, assertion);
	abort();
}

void gotr_assert_perror_fail(int errnum, const char *file, unsigned int line, const char *function)
{
	gotr_eprintf("Assertion failed in file %s line %d function %s:", file, line, function);
	abort();
}

void gotr_assert_gpgerr_fail(gcry_error_t errnum, const char *file, unsigned int line, const char *function)
{
	gotr_eprintf("Assertion failed in file %s line %d function %s: %s", file, line, function, gcry_strerror(errnum));
	abort();
}
