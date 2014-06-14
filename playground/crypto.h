#include <gcrypt.h>



// --- HASHING ---

struct GOTR_HashCode {
	uint32_t bits[512 / 8 / sizeof (uint32_t)];   /* = 16 */
};

void GOTR_hash(const void *block, size_t size, struct GOTR_HashCode *ret);



// --- MPI ---

void GOTR_mpi_print_unsigned(void *buf, size_t size, gcry_mpi_t val);



// --- EdDSA ---

struct GOTR_EddsaPrivateKey {
	unsigned char d[256 / 8];
};

struct GOTR_EddsaPublicKey {
	unsigned char q_y[256 / 8];
};

struct GOTR_EccSignaturePurpose {
	uint32_t size;// GNUNET_PACKED;
	uint32_t purpose;// GNUNET_PACKED;
};

struct GOTR_EddsaSignature {
	unsigned char r[256 / 8];
	unsigned char s[256 / 8];
};

void GOTR_eddsa_key_get_public(const struct GOTR_EddsaPrivateKey *priv, struct GOTR_EddsaPublicKey *pub);
//char *GOTR_eddsa_public_key_to_string(const struct GOTR_EddsaPublicKey *pub);
void GOTR_eddsa_key_clear(struct GOTR_EddsaPrivateKey *pk);
struct GOTR_EddsaPrivateKey *GOTR_eddsa_key_create();
int GOTR_eddsa_sign(const struct GOTR_EddsaPrivateKey *priv, const struct GOTR_EccSignaturePurpose *purpose, struct GOTR_EddsaSignature *sig);
int GOTR_eddsa_verify(uint32_t purpose, const struct GOTR_EccSignaturePurpose *validate, const struct GOTR_EddsaSignature *sig, const struct GOTR_EddsaPublicKey *pub);



// --- ECDHE ---

struct GOTR_EcdhePrivateKey {
	unsigned char d[256 / 8];
};

struct GOTR_EcdhePublicKey {
	unsigned char q_y[256 / 8];
};

void GOTR_ecdhe_key_get_public(const struct GOTR_EcdhePrivateKey *priv, struct GOTR_EcdhePublicKey *pub);