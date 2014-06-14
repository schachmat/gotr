#include <gcrypt.h>



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

struct gotr_EccSignaturePurpose {
	uint32_t size;// GNUNET_PACKED;
	uint32_t purpose;// GNUNET_PACKED;
};

struct gotr_EddsaSignature {
	unsigned char r[256 / 8];
	unsigned char s[256 / 8];
};

void gotr_eddsa_key_get_public(const struct gotr_eddsa_private_key *priv, struct gotr_eddsa_public_key *pub);
//char *gotr_eddsa_public_key_to_string(const struct gotr_eddsa_public_key *pub);
void gotr_eddsa_key_clear(struct gotr_eddsa_private_key *pk);
struct gotr_eddsa_private_key *gotr_eddsa_key_create();
int gotr_eddsa_sign(const struct gotr_eddsa_private_key *priv, const struct gotr_EccSignaturePurpose *purpose, struct gotr_EddsaSignature *sig);
int gotr_eddsa_verify(uint32_t purpose, const struct gotr_EccSignaturePurpose *validate, const struct gotr_EddsaSignature *sig, const struct gotr_eddsa_public_key *pub);



// --- ECDHE ---

struct gotr_EcdhePrivateKey {
	unsigned char d[256 / 8];
};

struct gotr_EcdhePublicKey {
	unsigned char q_y[256 / 8];
};

void gotr_ecdhe_key_get_public(const struct gotr_EcdhePrivateKey *priv, struct gotr_EcdhePublicKey *pub);
void gotr_ecdhe_key_clear(struct gotr_EcdhePrivateKey *pk);
struct gotr_EcdhePrivateKey *gotr_ecdhe_key_create();
int gotr_ecc_ecdh(const struct gotr_EcdhePrivateKey *priv, const struct gotr_EcdhePublicKey *pub, struct gotr_HashCode *key_material);



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
