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

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "key.h"
#include "util.h"

int load_privkey(const char* fname, struct gotr_dhe_skey *key)
{
	FILE *fp;
	const size_t size = sizeof(struct gotr_dhe_skey);

	if (!fname)
		return 0;

	if (!(fp = fopen(fname, "rb"))) {
		gotr_eprintf("could not open key file %s for reading:", fname);
		return 0;
	}

	if (size != fread(key, 1, size, fp)) {
		fclose(fp);
		gotr_eprintf("got invalid size reading key from file %s", fname);
		return 0;
	}
	fclose(fp);

	return 1;
}
