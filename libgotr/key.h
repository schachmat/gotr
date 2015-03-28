#ifndef _GOTR_KEY_H
#define _GOTR_KEY_H

/**
 * load the private key from file or generate a new one.
 *
 * @param abs_filename The absolut path to the file. If it does not exist yet
 * but the directory already exists, a generated key is saved there. If @a
 * abs_filename is NULL, a key is only generated but not saved.
 * @param key Where to store the loaded/generated key.
 */
void load_privkey(const char* abs_filename, struct gotr_dsa_skey *key);

#endif
