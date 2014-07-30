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

/**
 * initializes cryptographic constants.
 *
 * @return 1 on success, 0 on failure
 */
int gotr_gka_init();

void gotr_gka_exit();

/**
 * generate a BD key pair.
 *
 * @param[out] privkey The generated private BD key
 * @param[out] pubkey The generated public BD key
 */
void gotr_gen_BD_keypair(gcry_mpi_t* privkey, gcry_mpi_t* pubkey);

void gotr_ecbd_gen_keypair(gcry_mpi_t* privkey, gcry_mpi_point_t* pubkey);

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
 * calculate a flake key.
 * @f$ret = y0^{4r1} * R1^3 * R0^2 * V1 \pmod{prime}@f$
 *
 * @param[out] ret The calculated flake key
 * @param[in] y0
 * @param[in] r1
 * @param[in] R0
 * @param[in] R1
 * @param[in] V1
 * @return 1 on success, 0 on failure (unset parameter)
 */
int gotr_gen_BD_flake_key(gcry_mpi_t *ret, gcry_mpi_t y0, gcry_mpi_t r1, gcry_mpi_t R0, gcry_mpi_t R1, gcry_mpi_t V1);

int gotr_gen_BD_circle_key(gcry_mpi_t key, const struct gotr_user *users);

void gka_test();
#endif
