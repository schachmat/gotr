/**
 * This file is part of libgotr.
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

#ifndef _GOTR_BDGKA_H
#define _GOTR_BDGKA_H

#include <gcrypt.h>

/**
 * initializes cryptographic constants.
 *
 * @return 1 on success, 0 on failure
 */
int gotr_bdgka_init();

/**
 * generate a BD key pair.
 *
 * @param[out] privkey The generated private BD key
 * @param[out] pubkey The generated public BD key
 */
void gotr_gen_BD_keypair(gcry_mpi_t* privkey, gcry_mpi_t* pubkey);

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

int gotr_gen_BD_flake_key(struct gotr_user *user);

#endif
