#ifndef _GOTR_USER_H
#define _GOTR_USER_H

#include "crypto.h"
#include "util.h"

struct gotr_roomdata {
	struct gotr_auth_key my_circle_auth;
	struct gotr_sym_key my_circle_key;
	struct gotr_sym_iv my_circle_iv;
	struct gotr_dsa_skey my_dsa_skey;
	struct gotr_dsa_pkey my_dsa_pkey;
	struct gotr_user *users;         ///< a list of all users in the room
	const void *closure;
	char circle_valid;
};

typedef enum {
	GOTR_PAIR_CHAN_INIT,
	GOTR_PAIR_CHAN_ESTABLISH,
	GOTR_FLAKE_z,
	GOTR_FLAKE_R,
	GOTR_FLAKE_VALIDATE,
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
 * @var gotr_user::my_r
 * own (ephemeral) private key to this user.
 * @f$r_{ij0}@f$ and @f$r_{ij1}@f$
 * @var gotr_user::my_z
 * own corresponding (ephemeral) public keys.
 * @f$z_{ij0} = g^{r_{ij0}} \pmod{prime}@f$
 * and @f$z_{ij1} = g^{r_{ij1}} \pmod{prime}@f$
 * @var gotr_user::his_z
 * other users (ephemeral) public keys. Also called y.
 * @f$y_{ij0} = z_{ji0} = g^{r_{ji0}} \pmod{prime}@f$
 * and @f$y_{ij1} = z_{ji1} = g^{r_{ji1}} \pmod{prime}@f$
 * @var gotr_user::my_X
 * own X values for the flake key. Also called R.
 * @f$R_{ij0} = (\frac{z_{ij1}}{y_{ij0}})^{r_{ij0}} \pmod{prime}@f$
 * and @f$R_{ij1} = (\frac{y_{ij1}}{z_{ij0}})^{r_{ij1}} \pmod{prime}@f$
 * @var gotr_user::his_X
 * other users X values for the flake key. Also called V.
 * @f$V_{ij0} = R_{ji0} = (\frac{z_{ji1}}{y_{ji0}})^{r_{ji0}} \pmod{prime}@f$
 * and @f$V_{ij1} = R_{ji1} = (\frac{y_{ji1}}{z_{ji0}})^{r_{ji1}} \pmod{prime}@f$
 * @var gotr_user::our_flake_auth
 * the auth key derived from the flake key we agreed on with the other user.
 * This is used for authenticating the flake validation.
 * @var gotr_user::next
 * link to next user in the list
 * @var gotr_user::our_hmac_key
 * key to protect unicast messages HMAC with this user
 * @var gotr_user::our_sym_key
 * key to encrypt unicast messages with this user
 * @var gotr_user::our_sym_iv
 * iv for the unicast messages exchanged with this user
 * @var gotr_user::his_circle_auth
 * authentication key, this user will use for sending group messages
 * @var gotr_user::his_circle_key
 * encryption key, this user will use for sending group messages
 * @var gotr_user::his_circle_iv
 * initialization vector for encrypted group messages from this user
 */
struct gotr_user {
	struct gotr_auth_key his_circle_auth;
	struct gotr_sym_key  his_circle_key;
	struct gotr_sym_iv   his_circle_iv;
	struct gotr_auth_key our_flake_auth;
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
	struct gotr_user *next;
	const void *closure;
	gotr_msgtype next_expected_msgtype;
	gotr_msgtype next_sending_msgtype;
};

struct msg_pair_channel_init {
	struct gotr_dhe_pkey    sender_dhe_pkey;    /*     0    32 */
	/* size: 32 */
};

struct msg_pair_channel_est {
	struct gotr_hash_code       hmac;                   /*     0    64 */
	struct {
		struct gotr_dsa_sig     sig_sender_dhe_pkey;    /*    64    64 */
		struct gotr_dsa_pkey    sender_dsa_pkey;        /*   128    32 */
	} enc;                                              /*    64    96 */
	/* size: 160 */
};

struct msg_flake_z {
	struct gotr_hash_code    hmac;
	struct {
		struct gotr_point    sender_z[2];
	} enc;
};

struct msg_flake_R {
	struct gotr_hash_code    hmac;
	struct {
		struct gotr_point    sender_R[2];
	} enc;
};

struct msg_flake_validate {
	struct gotr_hash_code     hmac;
	struct {
		struct gotr_hash_code flake_hash;
	} enc;
};

struct msg_text_header {
	struct gotr_hash_code    hmac;
	uint32_t                 clen;
};

#endif
