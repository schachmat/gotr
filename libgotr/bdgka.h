#include <gcrypt.h>

/**
 * initializes cryptographic constants.
 *
 * @return 1 on success, 0 on failure
 */
int gotr_bdgka_init();

/**
 * generate a BD X value.
 * @f$ret = (\frac{num}{denom})^{pow} \pmod{prime}@f$
 *
 * @param[out] ret The calculated X value
 * @param[in] num The numerator
 * @param[in] denom The denominator
 * @param[in] pow The power
 * @return 1 on success, 0 on failure (if @p denom has no inverse)
 */
int gotr_gen_BD_X_value(gcry_mpi_t* ret, const gcry_mpi_t num, const gcry_mpi_t denom, const gcry_mpi_t pow);

/**
 * generate a BD key pair.
 *
 * @param[out] privkey The generated private BD key
 * @param[out] pubkey The generated public BD key
 */
void gotr_gen_BD_keypair(gcry_mpi_t* privkey, gcry_mpi_t* pubkey);
