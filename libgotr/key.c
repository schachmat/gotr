#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

#include "crypto.h"
#include "util.h"
#include "key.h"

void load_privkey(const char* abs_filename, struct gotr_dsa_skey *key)
{
	FILE *fp;
	size_t size = sizeof(struct gotr_dsa_skey);
	mode_t oldmask;

	if ((fp = fopen(abs_filename, "rb"))) {
		if (fread(key, 1, size, fp) == size) {
			fclose(fp);
			return;
		}
		fclose(fp);
	}

	gotr_eprintf("could not load private key from file:");
	gotr_eprintf("generating new private key, please wait...");
	gotr_eddsa_key_create(key);
	gotr_eprintf("done generating private key.");

	oldmask = umask(077);
	if ((fp = fopen(abs_filename, "wb"))) {
		if (fwrite(key, 1, size, fp) != size)
			gotr_eprintf("could not save private key to file");
		fclose(fp);
	} else {
		gotr_eprintf("could not open file for writing:");
	}
	umask(oldmask);
}
