/* This file is part of libgotr.
 * (C) 2014-2015 Markus Teich, Jannik Theiß
 *
 * libgotr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * libgotr is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libgotr; see the file LICENSE.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <errno.h>
#include <gcrypt.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gotr.h"
#include "util.h"

static void gotr_default_log(const char *format, ...);
static gotr_cb_log gotr_custom_logfn = &gotr_default_log;

void gotr_set_log_fn(gotr_cb_log fn)
{
	gotr_custom_logfn = fn ? fn : &gotr_default_log;
}

static void gotr_default_log(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

void gotr_eprintf(const char *format, ...)
{
	va_list ap;
	const size_t mlen = 2048;
	char msg[mlen];
	char *err = NULL;

	va_start(ap, format);
	vsnprintf(msg, mlen, format, ap);
	va_end(ap);
	msg[mlen-1] = '\0';

	if (format[0] != '\0' && format[strlen(format)-1] == ':')
		err = strerror(errno);

	gotr_custom_logfn("libgotr: %s%s%s\n", msg, err ? " " : "", err ? err : "");
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
