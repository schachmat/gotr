/* This file is part of libgotr.
 * (C) 2014 Markus Teich, Jannik Theiß
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

/**
 * @file gka.c
 * @brief Bourmester-Desmeth based hotplug capable Group Key Agreement modified
 * to use elliptic curves. See „Contributory Group Key Agreement Protocols,
 * Revisited for Mobile Ad-Hoc Groups“ by Mark Manulis†
 */

#include <assert.h>
#include <gcrypt.h>

#include "gka.h"
#include "util.h"

#define CURVE "Ed25519"
#define SERIALIZED_POINT_LEN (256/8)
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
static gcry_ctx_t edctx;

static gcry_mpi_t gotr_gen_private_BD_key();
static gcry_mpi_t gotr_gen_public_BD_key(const gcry_mpi_t privkey);
static int gotr_gen_BD_circle_key_part(gcry_mpi_t cur, gcry_mpi_t factors[4], unsigned int pow);

/// @todo return void
int gotr_gka_init()
{
	gcry_error_t rc = 0;

	generator = GCRYMPI_CONST_FOUR;
	if(gcry_mpi_scan(&prime, GCRYMPI_FMT_HEX, gotr_bd_prime, 0, NULL))
		return 0;
	gcry_mpi_set_flag(prime, GCRYMPI_FLAG_CONST);

	rc = gcry_mpi_ec_new(&edctx, NULL, CURVE);
	gotr_assert_gpgerr(rc);
	return 1;
}

void gotr_gka_exit()
{
	gcry_ctx_release(edctx);
}

static gcry_mpi_point_t deserialize_point(const unsigned char *data, const int len)
{
	gcry_sexp_t s;
	gcry_ctx_t ctx;
	gcry_mpi_point_t ret;
	gcry_error_t rc;

	rc = gcry_sexp_build(&s, NULL, "(public-key(ecc(curve " CURVE ")(q %b)))",
						 len, data);
	gotr_assert_gpgerr(rc);

	rc = gcry_mpi_ec_new(&ctx, s, NULL);
	gotr_assert_gpgerr(rc);
	gcry_sexp_release(s);

	ret = gcry_mpi_ec_get_point("q", ctx, 0);
	gotr_assert(ret);
	gcry_ctx_release(ctx);
	return ret;
}

static unsigned char *serialize_point(gcry_mpi_point_t p)
{
	gcry_sexp_t s;
	gcry_ctx_t ctx;
	gcry_error_t rc;
	gcry_mpi_t q;
	unsigned char *ret = malloc(SERIALIZED_POINT_LEN);

	rc = gcry_sexp_build(&s, NULL, "(public-key(ecc(curve " CURVE ")))");
	gotr_assert_gpgerr(rc);
	gotr_assert(NULL != s);

	rc = gcry_mpi_ec_new(&ctx, s, NULL);
	gotr_assert_gpgerr(rc);
	gcry_sexp_release(s);

	rc = gcry_mpi_ec_set_point("q", p, ctx);
	gotr_assert_gpgerr(rc);

	q = gcry_mpi_ec_get_mpi("q@eddsa", ctx, 0);
	gotr_assert(NULL != q);
	gcry_ctx_release(ctx);

	gotr_mpi_print_unsigned(ret, SERIALIZED_POINT_LEN, q);
	gcry_mpi_release(q);
	return ret;
}

void gotr_gen_BD_keypair(gcry_mpi_t* privkey, gcry_mpi_t* pubkey)
{
	*privkey = gotr_gen_private_BD_key();
	*pubkey = gotr_gen_public_BD_key(*privkey);
}

void gotr_ecbd_gen_keypair(gcry_mpi_t* privkey, gcry_mpi_point_t* pubkey)
{
	struct gotr_ecdhe_private_key priv;
	struct gotr_ecdhe_public_key pub;

	gotr_ecdhe_key_create(&priv);
	gotr_mpi_scan_unsigned(privkey, priv.d, sizeof(priv.d));

	gotr_ecdhe_key_get_public(&priv, &pub);
	*pubkey = deserialize_point(pub.q_y, (int)sizeof(pub.q_y));
}

void gotr_ecbd_gen_X_value(gcry_mpi_point_t* ret, const gcry_mpi_point_t succ, const gcry_mpi_point_t pred, const gcry_mpi_t priv)
{
	gcry_mpi_t tmp = gcry_mpi_new(0);
	gcry_mpi_point_t tmpoint = gcry_mpi_point_new(0);

	gotr_assert(succ && pred && priv);

	*ret = gcry_mpi_point_new(0);
	gcry_mpi_ec_mul(*ret, priv, succ, edctx);
	gcry_mpi_neg(tmp, priv);
	gcry_mpi_ec_mul(tmpoint, tmp, pred, edctx);
	gcry_mpi_ec_add(*ret, *ret, tmpoint, edctx);
	gcry_mpi_point_release(tmpoint);
	gcry_mpi_release(tmp);
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

int gotr_gen_BD_flake_key(gcry_mpi_t *ret,
		gcry_mpi_t y0,
		gcry_mpi_t r1,
		gcry_mpi_t R0,
		gcry_mpi_t R1,
		gcry_mpi_t V1)
{
	gcry_mpi_t tmp = gcry_mpi_new(GOTR_PKEYSIZE);

	if (!y0 || !r1 || !R0 || !R1 || !V1)
		return 0;

	/// @todo should we abort if the flake key already is calculated?
	*ret = gcry_mpi_new(GOTR_PKEYSIZE);

	gcry_mpi_powm(*ret, y0, GCRYMPI_CONST_FOUR, prime);
	gcry_mpi_powm(*ret, *ret, r1, prime);

	gcry_mpi_powm(tmp, R1, GCRYMPI_CONST_THREE, prime);
	gcry_mpi_mulm(*ret, *ret, tmp, prime);

	gcry_mpi_powm(tmp, R0, GCRYMPI_CONST_TWO, prime);
	gcry_mpi_mulm(*ret, *ret, tmp, prime);

	gcry_mpi_mulm(*ret, *ret, V1, prime);

	gcry_mpi_release(tmp);
	return 1;
}

/**
 * @todo docu
 */
int gotr_gen_BD_circle_key_part(gcry_mpi_t cur, gcry_mpi_t factors[4], unsigned int pow)
{
	gcry_mpi_t tmp = gcry_mpi_new(GOTR_PKEYSIZE);
	gcry_mpi_t n = gcry_mpi_set_ui(NULL, pow);

	if (!cur || !factors || !factors[0] || !factors [1] || !factors[2] || !factors[3] || !tmp)
		return 0;

	gcry_mpi_powm(tmp, factors[0], n, prime);
	gcry_mpi_mulm(cur, cur, tmp, prime);

	gcry_mpi_set_ui(n, --pow);
	gcry_mpi_powm(tmp, factors[1], n, prime);
	gcry_mpi_mulm(cur, cur, tmp, prime);

	gcry_mpi_set_ui(n, --pow);
	gcry_mpi_powm(tmp, factors[2], n, prime);
	gcry_mpi_mulm(cur, cur, tmp, prime);

	gcry_mpi_set_ui(n, --pow);
	gcry_mpi_powm(tmp, factors[3], n, prime);
	gcry_mpi_mulm(cur, cur, tmp, prime);

	gcry_mpi_release(tmp);
	gcry_mpi_release(n);
	return 1;
}

/**
 * @todo use W values instead of R
 */
int gotr_gen_BD_circle_key(gcry_mpi_t key, const struct gotr_user *users)
{
	const struct gotr_user *first = users;
	const struct gotr_user *pre;
	const struct gotr_user *cur;
	gcry_mpi_t factors[4];
	unsigned int pow = 0;

	while (first && first->expected_msgtype != GOTR_EXPECT_MSG)
		first = first->next;

	if (!users || !first)
		goto fail;

//	/* if there is only one other user, circle key is equal to flake key */
//	if (!users->next) {
//		*key = gcry_mpi_copy(users->flake_key);
//		return 1;
//	}

	pre = first;
	gcry_mpi_release(key);
	key = gcry_mpi_copy(GCRYMPI_CONST_ONE);

	for (cur = first->next; cur; cur = cur->next) {
		if (cur->expected_msgtype != GOTR_EXPECT_MSG)
			continue;
		factors[0] = cur->V[0];
		factors[1] = cur->R[1];
		factors[2] = pre->R[0];
		factors[3] = pre->V[1];
		gotr_gen_BD_circle_key_part(key, factors, pow += 4);
		pre = cur;
	}

	factors[0] = gcry_mpi_new(GOTR_PKEYSIZE);
	gcry_mpi_powm(factors[0], first->y[0], first->r[1], prime);
	factors[1] = first->R[1];
	factors[2] = pre->R[0];
	factors[3] = pre->V[1];
	gotr_gen_BD_circle_key_part(key, factors, pow + 4);

	return 1;
fail:
	gcry_mpi_release(key);
	return 0;
}

/**
 * generate a private BD key.
 * 
 * @return The generated private BD key
 */
static gcry_mpi_t gotr_gen_private_BD_key()
{
	gcry_mpi_t ret = gcry_mpi_new(GOTR_SKEYSIZE);
	gotr_rand_poll();
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
