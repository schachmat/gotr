/**
 * This file is part of libgotr.
 * (C) 2001-2014 Christian Grothoff, Nils Durner, Markus Teich, Jannik Theiß
 * (and other contributing authors)
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


#ifndef _GOTR_CRYPTO_H
#define _GOTR_CRYPTO_H

#include <gcrypt.h>
#include <stdint.h>

// --- RANDOM ---


void gotr_rand_poll();


// --- HASHING ---

struct gotr_hash_code {
	uint32_t bits[512 / 8 / sizeof (uint32_t)];   /* = 16 */
};

void gotr_hash(const void *block, size_t size, struct gotr_hash_code *ret);



// --- MPI ---

void gotr_mpi_print_unsigned(void *buf, size_t size, gcry_mpi_t val);
void gotr_mpi_scan_unsigned (gcry_mpi_t *result, const void *data, size_t size);



// --- EdDSA ---

struct gotr_dsa_skey {
	unsigned char d[256 / 8];
};

struct gotr_dsa_pkey {
	unsigned char q_y[256 / 8];
};

struct gotr_dsa_sig {
	unsigned char r[256 / 8];
	unsigned char s[256 / 8];
};

void gotr_eddsa_key_create(struct gotr_dsa_skey *priv);
void gotr_eddsa_key_get_public(const struct gotr_dsa_skey *priv, struct gotr_dsa_pkey *pub);
int gotr_eddsa_sign(const struct gotr_dsa_skey *priv, const void *block, size_t size, struct gotr_dsa_sig *sig);
int gotr_eddsa_verify(const struct gotr_dsa_pkey *pub, const void *block, size_t size, const struct gotr_dsa_sig *sig);
void gotr_eddsa_key_clear(struct gotr_dsa_skey *priv);



// --- ECDHE ---

struct gotr_dhe_skey {
	unsigned char d[256 / 8];
};

struct gotr_dhe_pkey {
	unsigned char q_y[256 / 8];
};

void gotr_ecdhe_key_create(struct gotr_dhe_skey *priv);
void gotr_ecdhe_key_get_public(const struct gotr_dhe_skey *priv, struct gotr_dhe_pkey *pub);
int gotr_ecdhe(const struct gotr_dhe_skey *priv, const struct gotr_dhe_pkey *pub, struct gotr_hash_code *key_material);
void gotr_ecdhe_key_clear(struct gotr_dhe_skey *priv);



// --- Symmetric ---

#define gotr_AES_KEY_LENGTH (256/8)

struct gotr_sym_key {
	unsigned char aes_key[gotr_AES_KEY_LENGTH];
	unsigned char twofish_key[gotr_AES_KEY_LENGTH];
};

struct gotr_sym_iv {
	unsigned char aes_iv[gotr_AES_KEY_LENGTH / 2];
	unsigned char twofish_iv[gotr_AES_KEY_LENGTH / 2];
};

void gotr_symmetric_create_session_key(struct gotr_sym_key *key);
ssize_t gotr_symmetric_encrypt(const void *block, size_t size, const struct gotr_sym_key *sessionkey, const struct gotr_sym_iv *iv, void *result);
ssize_t gotr_symmetric_decrypt(const void *block, size_t size, const struct gotr_sym_key *sessionkey, const struct gotr_sym_iv *iv, void *result);
void gotr_symmetric_derive_iv(struct gotr_sym_iv *iv, const struct gotr_sym_key *skey, const void *salt, size_t salt_len, ...);
void gotr_symmetric_derive_iv_v (struct gotr_sym_iv *iv, const struct gotr_sym_key *skey, const void *salt, size_t salt_len, va_list argp);



// --- KDF ---

int gotr_kdf_v (void *result, size_t out_len, const void *xts, size_t xts_len, const void *skm, size_t skm_len, va_list argp);
int gotr_hkdf_v (void *result, size_t out_len, int xtr_algo, int prf_algo, const void *xts, size_t xts_len, const void *skm, size_t skm_len, va_list argp);

#endif
