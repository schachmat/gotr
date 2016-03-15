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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

#include "crypto.h"
#include "util.h"
#include "key.h"

void load_privkey(const char* abs_filename, struct gotr_dhe_skey *key)
{
	FILE *fp;
	size_t size = sizeof(struct gotr_dhe_skey);

	if (!abs_filename)
		goto create;

	if (!(fp = fopen(abs_filename, "rb"))) {
		gotr_eprintf("could not open file %s for reading:", abs_filename);
		goto create;
	}

	if (size == fread(key, 1, size, fp)) {
		fclose(fp);
		return;
	}
	fclose(fp);
	gotr_eprintf("could not read private key from file %s", abs_filename);

create:
	gotr_ecdhe_key_create(key);
}
