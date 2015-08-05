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
	mode_t oldmask;

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
//	gotr_eprintf("generating new private key, please wait...");
	gotr_ecdhe_key_create(key);
//	gotr_eprintf("done generating private key.");

	if (!abs_filename)
		return;

	oldmask = umask(077);
	if ((fp = fopen(abs_filename, "wb"))) {
		if (fwrite(key, 1, size, fp) != size)
			gotr_eprintf("could not write private key to file %s", abs_filename);
		fclose(fp);
	} else {
		gotr_eprintf("could not open file %s for writing:", abs_filename);
	}
	umask(oldmask);
}
