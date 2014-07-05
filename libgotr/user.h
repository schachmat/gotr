#ifndef _GOTR_USER_H
#define _GOTR_USER_H

#include "crypto.h"

struct gotr_roomdata {
	const void *closure;
	struct gotr_eddsa_private_key my_privkey;
	struct gotr_eddsa_public_key my_pubkey;
	struct gotr_user *users;         ///< a list of all users in the room
};

typedef enum {
	GOTR_STATE_UNKNOWN,
	GOTR_STATE_CHANNEL_ESTABLISHED,
	GOTR_STATE_FLAKE_GOT_y,
	GOTR_STATE_FLAKE_GOT_V,
	GOTR_STATE_FLAKE_VALIDATED,
} GOTR_STATE;

/**
 * stores key material and other information related to a specific user
 *
 * @var gotr_user::closure
 * a pointer that is given to the callbacks when referring to this user.
 * @var gotr_user::state
 * progress in the key exchange algorithm.
 * @var gotr_user::user_pubkey
 * the long term static key of this user.
 * @var gotr_user::r
 * own (ephemeral) private key to this user.
 * @f$r_{ij0}@f$ and @f$r_{ij1}@f$
 * @var gotr_user::z
 * own corresponding (ephemeral) public keys.
 * @f$z_{ij0} = g^{r_{ij0}} \mod{prime}@f$
 * and @f$z_{ij1} = g^{r_{ij1}} \mod{prime}@f$
 * @var gotr_user::y
 * other users (ephemeral) public keys.
 * @f$y_{ij0} = z_{ji0} = g^{r_{ji0}} \mod{prime}@f$
 * and @f$y_{ij1} = z_{ji1} = g^{r_{ji1}} \mod{prime}@f$
 * @var gotr_user::R
 * own X values for the flake key.
 * @f$R_{ij0} = (\frac{z_{ij1}}{y_{ij0}})^{r_{ij0}} \mod{prime}@f$
 * and @f$R_{ij1} = (\frac{y_{ij1}}{z_{ij0}})^{r_{ij1}} \mod{prime}@f$
 * @var gotr_user::V
 * other users X values for the flake key.
 * @f$V_{ij0} = R_{ji0} = (\frac{z_{ji1}}{y_{ji0}})^{r_{ji0}} \mod{prime}@f$
 * and @f$V_{ij1} = R_{ji1} = (\frac{y_{ji1}}{z_{ji0}})^{r_{ji1}} \mod{prime}@f$
 * @var gotr_user::next
 * link to next user in the list
 * @todo cleanup function to free all members
 * @todo move crypto parameters to private data structure not visible/writable
 * by host
 */
struct gotr_user {
	void *closure;
	GOTR_STATE state;
	struct gotr_eddsa_public_key user_pubkey;
	struct gotr_EcdhePrivateKey dhe_privkey;
	struct gotr_EcdhePublicKey dhe_pubkey;
	gcry_mpi_t r[2];
	gcry_mpi_t z[2];
	gcry_mpi_t y[2];
	gcry_mpi_t R[2];
	gcry_mpi_t V[2];
	gcry_mpi_t flake_key;
	struct gotr_user *next;
};

#endif
