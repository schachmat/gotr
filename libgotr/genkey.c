/* This file is part of libgotr.
 * (C) 2014-2015 Markus Teich
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

#include <sys/stat.h>

#include "util.h"
#include "crypto.h"

int main(int argc, char *argv[])
{
	FILE *fp;
	size_t size = sizeof(struct gotr_dhe_skey);
	mode_t oldmask;
	struct gotr_dhe_skey key;

	if (argc != 2 || !argv[1]) {
		gotr_eprintf("usage: gotr_genkey FILENAME");
		return 1;
	}

	if (!gcry_check_version(GOTR_GCRYPT_VERSION)) {
		gotr_eprintf("libgcrypt version mismatch");
		return 1;
	}

	/* Do not set GCRYCTL_ENABLE_QUICK_RANDOM here so GCRY_VERY_STRONG_RANDOM is
	 * used for the key generation */

	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	gotr_ecdhe_key_create(&key);

	oldmask = umask(0077);
	if ((fp = fopen(argv[1], "wb"))) {
		if (fwrite(&key, 1, size, fp) != size)
			gotr_eprintf("could not write private key to file %s", argv[1]);
		fclose(fp);
	} else {
		gotr_eprintf("could not open file %s for writing:", argv[1]);
	}
	umask(oldmask);

	return 0;
}
