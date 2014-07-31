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

struct gotr_HashCode {
	uint32_t bits[512 / 8 / sizeof (uint32_t)];   /* = 16 */
};

void gotr_hash(const void *block, size_t size, struct gotr_HashCode *ret);



// --- MPI ---

void gotr_mpi_print_unsigned(void *buf, size_t size, gcry_mpi_t val);
void gotr_mpi_scan_unsigned (gcry_mpi_t *result, const void *data, size_t size);



// --- EdDSA ---

struct gotr_eddsa_private_key {
	unsigned char d[256 / 8];
};

struct gotr_eddsa_public_key {
	unsigned char q_y[256 / 8];
};

struct gotr_eddsa_signature {
	unsigned char r[256 / 8];
	unsigned char s[256 / 8];
};

void gotr_eddsa_key_create(struct gotr_eddsa_private_key *priv);
void gotr_eddsa_key_get_public(const struct gotr_eddsa_private_key *priv, struct gotr_eddsa_public_key *pub);
int gotr_eddsa_sign(const struct gotr_eddsa_private_key *priv, const void *block, size_t size, struct gotr_eddsa_signature *sig);
int gotr_eddsa_verify(const struct gotr_eddsa_public_key *pub, const void *block, size_t size, const struct gotr_eddsa_signature *sig);
void gotr_eddsa_key_clear(struct gotr_eddsa_private_key *priv);



// --- ECDHE ---

struct gotr_ecdhe_private_key {
	unsigned char d[256 / 8];
};

struct gotr_ecdhe_public_key {
	unsigned char q_y[256 / 8];
};

void gotr_ecdhe_key_create(struct gotr_ecdhe_private_key *priv);
void gotr_ecdhe_key_get_public(const struct gotr_ecdhe_private_key *priv, struct gotr_ecdhe_public_key *pub);
int gotr_ecdhe(const struct gotr_ecdhe_private_key *priv, const struct gotr_ecdhe_public_key *pub, struct gotr_HashCode *key_material);
void gotr_ecdhe_key_clear(struct gotr_ecdhe_private_key *priv);



// --- Symmetric ---

#define gotr_AES_KEY_LENGTH (256/8)

struct gotr_SymmetricSessionKey {
	unsigned char aes_key[gotr_AES_KEY_LENGTH];
	unsigned char twofish_key[gotr_AES_KEY_LENGTH];
};

struct gotr_SymmetricInitializationVector {
	unsigned char aes_iv[gotr_AES_KEY_LENGTH / 2];
	unsigned char twofish_iv[gotr_AES_KEY_LENGTH / 2];
};

void gotr_symmetric_create_session_key(struct gotr_SymmetricSessionKey *key);
ssize_t gotr_symmetric_encrypt(const void *block, size_t size, const struct gotr_SymmetricSessionKey *sessionkey, const struct gotr_SymmetricInitializationVector *iv, void *result);
ssize_t gotr_symmetric_decrypt(const void *block, size_t size, const struct gotr_SymmetricSessionKey *sessionkey, const struct gotr_SymmetricInitializationVector *iv, void *result);
void gotr_symmetric_derive_iv(struct gotr_SymmetricInitializationVector *iv, const struct gotr_SymmetricSessionKey *skey, const void *salt, size_t salt_len, ...);
void gotr_symmetric_derive_iv_v (struct gotr_SymmetricInitializationVector *iv, const struct gotr_SymmetricSessionKey *skey, const void *salt, size_t salt_len, va_list argp);



// --- KDF ---

int gotr_kdf_v (void *result, size_t out_len, const void *xts, size_t xts_len, const void *skm, size_t skm_len, va_list argp);
int gotr_hkdf_v (void *result, size_t out_len, int xtr_algo, int prf_algo, const void *xts, size_t xts_len, const void *skm, size_t skm_len, va_list argp);

#endif
