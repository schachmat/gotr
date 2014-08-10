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

gcry_mpi_point_t deserialize_point(const struct gotr_point* data, const int len)
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

void serialize_point(struct gotr_point *buf, const size_t len, const gcry_mpi_point_t p)
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

int gotr_point_cmp(const gcry_mpi_point_t a, const gcry_mpi_point_t b)
{
	gcry_mpi_t ax = gcry_mpi_new(0);
	gcry_mpi_t ay = gcry_mpi_new(0);
	gcry_mpi_t bx = gcry_mpi_new(0);
	gcry_mpi_t by = gcry_mpi_new(0);
	if (gcry_mpi_ec_get_affine(ax, ay, a, edctx) ||
		gcry_mpi_ec_get_affine(bx, by, b, edctx))
		return 1;
	return gcry_mpi_cmp(ax, bx) || gcry_mpi_cmp(ay, by);
}

void gotr_ecbd_gen_keypair(gcry_mpi_t* privkey, gcry_mpi_point_t* pubkey)
{
	struct gotr_dhe_skey priv;
	struct gotr_dhe_pkey pub;

	gotr_rand_poll();
	gotr_ecdhe_key_create(&priv);
	gotr_mpi_scan_unsigned(privkey, priv.d, sizeof(priv.d));

	gotr_ecdhe_key_get_public(&priv, &pub);
	*pubkey = deserialize_point(pub.q_y, sizeof(pub.q_y));
}

void gotr_ecbd_gen_X_value(gcry_mpi_point_t* ret, const gcry_mpi_point_t succ, const gcry_mpi_point_t pred, const gcry_mpi_t priv)
{
	gcry_mpi_t x = gcry_mpi_new(0);
	gcry_mpi_t y = gcry_mpi_new(0);
	gcry_mpi_t z = gcry_mpi_new(0);
	gcry_mpi_point_t tmpoint = gcry_mpi_point_new(0);

	gotr_assert(succ && pred && priv);

	///@todo use gcry_mpi_ec_sub after it is released
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

void gotr_ecbd_gen_flake_key(gcry_mpi_point_t *ret,
							 gcry_mpi_point_t y0,
							 gcry_mpi_t r1,
							 gcry_mpi_point_t R1,
							 gcry_mpi_point_t R0,
							 gcry_mpi_point_t V1)
{
	gcry_mpi_point_t tmp = gcry_mpi_point_new(0);
	gcry_mpi_t n = gcry_mpi_new(0);

	*ret = gcry_mpi_point_new(0);

	gcry_mpi_mul_ui(n, r1, 4);
	gcry_mpi_ec_mul(*ret, n, y0, edctx);

	gcry_mpi_set_ui(n, 3);
	gcry_mpi_ec_mul(tmp, n, R1, edctx);
	gcry_mpi_ec_add(*ret, *ret, tmp, edctx);

	gcry_mpi_ec_dup(tmp, R0, edctx);
	gcry_mpi_ec_add(*ret, *ret, tmp, edctx);

	gcry_mpi_ec_add(*ret, *ret, V1, edctx);

	gcry_mpi_point_release(tmp);
	gcry_mpi_release(n);
	gcry_log_debugpnt("flake", *ret, edctx);
}

void gotr_ecbd_gen_circle_key(gcry_mpi_point_t *ret, gcry_mpi_point_t *X,
							  gcry_mpi_point_t Z, gcry_mpi_t r)
{
	gcry_mpi_point_t tmp = gcry_mpi_point_new(0);
	gcry_mpi_t n = gcry_mpi_new(0);
	unsigned int i;

	*ret = gcry_mpi_point_set(NULL, NULL, GCRYMPI_CONST_ONE, GCRYMPI_CONST_ONE);
	for (i = 0; X[i]; i++) {
		gcry_mpi_set_ui(n, i+1);
		gcry_mpi_ec_mul(tmp, n, X[i], edctx);
		gcry_mpi_ec_add(*ret, *ret, tmp, edctx);
	}

	gcry_mpi_mul_ui(n, r, i+1);
	gcry_mpi_ec_mul(tmp, n, Z, edctx);
	gcry_mpi_ec_add(*ret, *ret, tmp, edctx);
	gcry_mpi_release(n);
	gcry_mpi_point_release(tmp);
}
