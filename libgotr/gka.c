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
 * Revisited for Mobile Ad-Hoc Groups“ by Mark Manulis
 */

#include <gcrypt.h>

#include "gka.h"
#include "util.h"

#define CURVE "Ed25519"

static gcry_ctx_t edctx;

void gotr_gka_init()
{
	gcry_error_t rc = 0;

	rc = gcry_mpi_ec_new(&edctx, NULL, CURVE);
	gotr_assert_gpgerr(rc);
}

void gotr_gka_exit()
{
	gcry_ctx_release(edctx);
}

void gotr_dbgpnt(const char* name, gcry_mpi_point_t p)
{
	gcry_log_debugpnt(name, p, edctx);
}

gcry_mpi_point_t deserialize_point(const unsigned char *data, const int len)
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

void serialize_point(unsigned char *buf, const size_t len, const gcry_mpi_point_t p)
{
	gcry_sexp_t s;
	gcry_ctx_t ctx;
	gcry_error_t rc;
	gcry_mpi_t q;

	gotr_assert(buf && len >= SERIALIZED_POINT_LEN);

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

	gotr_mpi_print_unsigned(buf, len, q);
	gcry_mpi_release(q);
}

void gotr_ecbd_gen_keypair(gcry_mpi_t* privkey, gcry_mpi_point_t* pubkey)
{
	struct gotr_dhe_skey priv;
	struct gotr_dhe_pkey pub;

	gotr_rand_poll();
	gotr_ecdhe_key_create(&priv);
	gotr_mpi_scan_unsigned(privkey, priv.d, sizeof(priv.d));

	gotr_ecdhe_key_get_public(&priv, &pub);
	*pubkey = deserialize_point(pub.q_y, (int)sizeof(pub.q_y));
}

void gotr_ecbd_gen_X_value(gcry_mpi_point_t* ret, const gcry_mpi_point_t succ, const gcry_mpi_point_t pred, const gcry_mpi_t priv)
{
	gcry_mpi_t x = gcry_mpi_new(0);
	gcry_mpi_t y = gcry_mpi_new(0);
	gcry_mpi_t z = gcry_mpi_new(0);
	gcry_mpi_point_t tmpoint = gcry_mpi_point_new(0);

	gotr_assert(succ && pred && priv);

	*ret = gcry_mpi_point_new(0);
	gcry_mpi_point_get(x, y, z, pred);
	gcry_mpi_neg(x, x);
	gcry_mpi_point_set(tmpoint, x, y, z);
	gcry_mpi_ec_add(tmpoint, succ, tmpoint, edctx);
	gcry_mpi_ec_mul(*ret, priv, tmpoint, edctx);

	gcry_mpi_point_release(tmpoint);
	gcry_mpi_release(x);
	gcry_mpi_release(y);
	gcry_mpi_release(z);
}

void gotr_ecbd_gen_circle_key_part(gcry_mpi_point_t cur, gcry_mpi_point_t x[4], unsigned int fac)
{
	gcry_mpi_point_t tmp = gcry_mpi_point_new(0);
	gcry_mpi_t n = gcry_mpi_set_ui(NULL, fac);

	gcry_mpi_ec_mul(tmp, n, x[0], edctx);
	gcry_mpi_ec_add(cur, cur, tmp, edctx);

	gcry_mpi_set_ui(n, --fac);
	gcry_mpi_ec_mul(tmp, n, x[1], edctx);
	gcry_mpi_ec_add(cur, cur, tmp, edctx);

	gcry_mpi_set_ui(n, --fac);
	gcry_mpi_ec_mul(tmp, n, x[2], edctx);
	gcry_mpi_ec_add(cur, cur, tmp, edctx);

	gcry_mpi_set_ui(n, --fac);
	gcry_mpi_ec_mul(tmp, n, x[3], edctx);
	gcry_mpi_ec_add(cur, cur, tmp, edctx);

	gcry_mpi_point_release(tmp);
	gcry_mpi_release(n);
}

void gotr_ecbd_gen_flake_key(gcry_mpi_point_t *ret,
						gcry_mpi_point_t y0,
						gcry_mpi_t r1,
						gcry_mpi_point_t R1,
						gcry_mpi_point_t R0,
						gcry_mpi_point_t V1)
{
	gcry_mpi_point_t X[4];

	*ret = gcry_mpi_point_set(NULL, NULL, GCRYMPI_CONST_ONE, GCRYMPI_CONST_ONE);
	X[0] = gcry_mpi_point_new(0);
	gcry_mpi_ec_mul(X[0], r1, y0, edctx);
	X[1] = R1;
	X[2] = R0;
	X[3] = V1;
	gotr_ecbd_gen_circle_key_part(*ret, X, 4);
	gcry_log_debugpnt("flake", *ret, edctx);
}

/**
 * @todo use W values instead of R
 */
int gotr_gen_BD_circle_key(gcry_mpi_t key, const struct gotr_user *users)
{
/*	const struct gotr_user *first = users;
	const struct gotr_user *pre;
	const struct gotr_user *cur;
	gcry_mpi_t factors[4];
	unsigned int pow = 0;

	while (first && first->expected_msgtype != GOTR_EXPECT_MSG)
		first = first->next;

	if (!users || !first)
		goto fail;
*/
//	/* if there is only one other user, circle key is equal to flake key */
//	if (!users->next) {
//		*key = gcry_mpi_copy(users->flake_key);
//		return 1;
//	}
/*
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
*/	return 0;
}
