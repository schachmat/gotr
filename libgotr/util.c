#include <errno.h>
#include <gcrypt.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "util.h"


void gotr_rand_poll()
{
	static unsigned char rand_amount = 255;
	if(!(rand_amount--))
		gcry_fast_random_poll();
}

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
