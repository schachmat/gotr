/* Bourmester-Desmeth Group Key Agreement */

#include <gcrypt.h>

#include "libgotr.h"
#include "bdgka.h"

#define GOTR_SKEYSIZE (4096)
#define GOTR_PKEYSIZE (GOTR_SKEYSIZE+1)

/* group parameters from http://tools.ietf.org/html/rfc3526 */
static const char *gotr_bd_prime =
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
		"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
		"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
		"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
		"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
		"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
		"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
		"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
		"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
		"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
		"FFFFFFFFFFFFFFFF";

static gcry_mpi_t prime;
static gcry_mpi_t generator;

static gcry_mpi_t gotr_gen_private_BD_key();
static gcry_mpi_t gotr_gen_public_BD_key(const gcry_mpi_t privkey);

int gotr_bdgka_init()
{
	generator = GCRYMPI_CONST_FOUR;
	if(gcry_mpi_scan(&prime, GCRYMPI_FMT_HEX, gotr_bd_prime, 0, NULL))
		return 0;
	gcry_mpi_set_flag(prime, GCRYMPI_FLAG_CONST);
	return 1;
}

void gotr_gen_BD_keypair(gcry_mpi_t* privkey, gcry_mpi_t* pubkey)
{
	*privkey = gotr_gen_private_BD_key();
	*pubkey = gotr_gen_public_BD_key(*privkey);
}

int gotr_gen_BD_X_value(gcry_mpi_t* ret, const gcry_mpi_t num, const gcry_mpi_t denom, const gcry_mpi_t pow)
{
	*ret = gcry_mpi_new(GOTR_PKEYSIZE);
	if (!gcry_mpi_invm(*ret, denom, prime))
		return 0;
	gcry_mpi_mulm(*ret, *ret, num, prime);
	gcry_mpi_powm(*ret, *ret, pow, prime);
	return 1;
}

int gotr_gen_BD_flake_key(struct gotr_user *user)
{
	gcry_mpi_t tmp = gcry_mpi_new(GOTR_PKEYSIZE);

	if (!user || !user->y[0] || !user->r[1] || !user->R[0] || !user->R[1] || !user->V[1])
		return 0;

	/// @todo should we abort if the flake key already is calculated?
	user->flake_key = gcry_mpi_new(GOTR_PKEYSIZE);

	gcry_mpi_powm(user->flake_key, user->y[0], GCRYMPI_CONST_FOUR, prime);
	gcry_mpi_powm(user->flake_key, user->flake_key, user->r[1], prime);

	gcry_mpi_powm(tmp, user->R[1], GCRYMPI_CONST_THREE, prime);
	gcry_mpi_mulm(user->flake_key, user->flake_key, tmp, prime);

	gcry_mpi_powm(tmp, user->R[0], GCRYMPI_CONST_TWO, prime);
	gcry_mpi_mulm(user->flake_key, user->flake_key, tmp, prime);

	gcry_mpi_mulm(user->flake_key, user->flake_key, user->V[1], prime);

	gcry_mpi_release(tmp);
	return 1;
}

/**
 * generate a private BD key.
 * 
 * @return The generated private BD key
 */
static gcry_mpi_t gotr_gen_private_BD_key()
{
	gcry_mpi_t ret = gcry_mpi_new(GOTR_SKEYSIZE);
	do {
		gcry_mpi_randomize(ret, GOTR_SKEYSIZE, GCRY_STRONG_RANDOM);
	} while (!gcry_mpi_cmp_ui(ret, 0));
	return ret;
}

/**
 * generate a public BD key.
 *
 * @param privkey The corresponding private BD key
 * @return The public BD key to @p privkey
 */
static gcry_mpi_t gotr_gen_public_BD_key(const gcry_mpi_t privkey)
{
	gcry_mpi_t ret = gcry_mpi_new(GOTR_PKEYSIZE);
	gcry_mpi_powm(ret, generator, privkey, prime);
	return ret;
}
