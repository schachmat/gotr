#ifndef _GOTR_USER_H
#define _GOTR_USER_H

#include "crypto.h"

struct gotr_roomdata {
	struct gotr_dsa_skey my_dsa_skey;
	struct gotr_dsa_pkey my_dsa_pkey;
	struct gotr_user *users;         ///< a list of all users in the room
	const void *closure;
};

typedef enum {
	GOTR_PAIR_CHAN_INIT,
	GOTR_PAIR_CHAN_ESTABLISH,
	GOTR_FLAKE_z,
	GOTR_FLAKE_R,
	GOTR_MSG,
	GOTR_MAX_MSGTYPES
} gotr_msgtype;

/**
 * @struct gotr_user user.h user.h
 * stores key material and other information related to a specific user.
 * This struct represents the cryptographic state of our channel to this other
 * user.
 *
 * @var gotr_user::closure
 * a pointer that is given to the callbacks when referring to this user.
 * @var gotr_user::next_expected_msgtype
 * the next message from the other user should have this type.
 * @var gotr_user::next_sending_msgtype
 * the next message, we send to the other user should have the given type.
 * @var gotr_user::his_dsa_pkey
 * other users long term public key for EDDSA.
 * @var gotr_user::my_dhe_skey
 * own private key for the ECDHE
 * @var gotr_user::his_dhe_pkey
 * other users public key for the ECDHE
 * @var gotr_user::r
 * own (ephemeral) private key to this user.
 * @f$r_{ij0}@f$ and @f$r_{ij1}@f$
 * @var gotr_user::z
 * own corresponding (ephemeral) public keys.
 * @f$z_{ij0} = g^{r_{ij0}} \pmod{prime}@f$
 * and @f$z_{ij1} = g^{r_{ij1}} \pmod{prime}@f$
 * @var gotr_user::y
 * other users (ephemeral) public keys.
 * @f$y_{ij0} = z_{ji0} = g^{r_{ji0}} \pmod{prime}@f$
 * and @f$y_{ij1} = z_{ji1} = g^{r_{ji1}} \pmod{prime}@f$
 * @var gotr_user::R
 * own X values for the flake key.
 * @f$R_{ij0} = (\frac{z_{ij1}}{y_{ij0}})^{r_{ij0}} \pmod{prime}@f$
 * and @f$R_{ij1} = (\frac{y_{ij1}}{z_{ij0}})^{r_{ij1}} \pmod{prime}@f$
 * @var gotr_user::V
 * other users X values for the flake key.
 * @f$V_{ij0} = R_{ji0} = (\frac{z_{ji1}}{y_{ji0}})^{r_{ji0}} \pmod{prime}@f$
 * and @f$V_{ij1} = R_{ji1} = (\frac{y_{ji1}}{z_{ji0}})^{r_{ji1}} \pmod{prime}@f$
 * @var gotr_user::flake_key
 * the flake key we agreed on with the other user
 * @var gotr_user::next
 * link to next user in the list
 */
struct gotr_user {
	struct gotr_auth_key our_hmac_key;
	struct gotr_sym_key  our_sym_key;
	struct gotr_sym_iv   our_sym_iv;
	struct gotr_dhe_skey my_dhe_skey;
	struct gotr_dhe_pkey his_dhe_pkey;
	struct gotr_dsa_pkey his_dsa_pkey;
	gcry_mpi_t my_r[2];
	gcry_mpi_point_t my_z[2];
	gcry_mpi_point_t his_z[2];
	gcry_mpi_point_t my_X[2];
	gcry_mpi_point_t his_X[2];
	gcry_mpi_point_t our_flake_key;
	struct gotr_user *next;
	const void *closure;
	gotr_msgtype next_expected_msgtype;
	gotr_msgtype next_sending_msgtype;
};

#endif
