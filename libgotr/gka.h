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
 * @file gka.h
 * @brief Bourmester-Desmeth based hotplug capable Group Key Agreement
 */

#ifndef _GOTR_GKA_H
#define _GOTR_GKA_H

#include <gcrypt.h>

#include "util.h"
#include "user.h"
#include "messaging.h"

#define SERIALIZED_POINT_LEN (256/8)

/**
 * initializes cryptographic constants.
 */
void gotr_gka_init();

void gotr_gka_exit();

struct gotr_point {
	unsigned char data[SERIALIZED_POINT_LEN];
};

void gotr_dbgpnt(const char* name, gcry_mpi_point_t p);
gcry_mpi_point_t deserialize_point(const unsigned char *data, const int len);
void serialize_point(unsigned char *buf, const size_t len, const gcry_mpi_point_t p);

/**
 * generate a ECBD key pair.
 *
 * @param[out] privkey The generated private BD key
 * @param[out] pubkey The generated public BD key
 */
void gotr_ecbd_gen_keypair(gcry_mpi_t* privkey, gcry_mpi_point_t* pubkey);

/**
 * calculate a flake key.
 * @f$ret = 4*y0*r1 + 3*R1 + 2*R0 + V1@f$
 *
 * @param[out] ret The calculated flake key
 * @param[in] y0
 * @param[in] r1
 * @param[in] R1
 * @param[in] R0
 * @param[in] V1
 */
void gotr_ecbd_gen_flake_key(gcry_mpi_point_t *ret,
						gcry_mpi_point_t y0,
						gcry_mpi_t r1,
						gcry_mpi_point_t R1,
						gcry_mpi_point_t R0,
						gcry_mpi_point_t V1);

/**
 * generate an ECBD X value.
 * @f$ret = priv(succ-pred)@f$
 *
 * @param[out] ret The calculated X value
 * @param[in] succ The ECBD public key of the successing node
 * @param[in] pred The ECBD public key of the predecessing node
 * @param[in] priv The ECBD private key
 */
void gotr_ecbd_gen_X_value(gcry_mpi_point_t* ret, const gcry_mpi_point_t succ, const gcry_mpi_point_t pred, const gcry_mpi_t priv);


int gotr_gen_BD_circle_key(gcry_mpi_t key, const struct gotr_user *users);
#endif
