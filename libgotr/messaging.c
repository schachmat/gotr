#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <gcrypt.h>
#include <arpa/inet.h>

#include "user.h"
#include "util.h"
#include "crypto.h"
#include "gotr.h"
#include "b64.h"
#include "gka.h"

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

static inline int check_params_create_msg(const struct gotr_roomdata *room,
										  struct gotr_user *user,
										  void **msg,
										  size_t len,
										  char *msgtype)
{
	if(!room || !(*msg = malloc(len))) {
		gotr_eprintf("packing %s failed for %s:", msgtype, user->closure);
		return 0;
	}

	gotr_eprintf("packing %s for %s", msgtype, user->closure);
	memset(*msg, 0, len);
	return 1;
}

static inline unsigned char *encrypt_and_hmac(struct gotr_user *user,
											  unsigned char *msg,
											  size_t msglen,
											  size_t *len,
											  gotr_msgtype next_type)
{
	void *enc = msg + sizeof(struct gotr_hash_code);
	const size_t enclen = msglen - sizeof(struct gotr_hash_code);

	if (gotr_symmetric_encrypt(enc, enclen, &user->our_sym_key,
							   &user->our_sym_iv, enc) != enclen) {
		gotr_eprintf("could not encrypt msg");
		return NULL;
	}
	gotr_hmac(&user->our_hmac_key, enc, enclen, (struct gotr_hash_code *)msg);

	user->next_sending_msgtype = next_type;
	*len = msglen;
	return msg;
}

static inline int check_hmac_decrypt(struct gotr_roomdata *room,
									 struct gotr_user *user,
									 unsigned char *packed_msg,
									 size_t len,
									 size_t len_should,
									 const char* msgtype)
{
	struct gotr_hash_code hmac;
	void *enc = packed_msg + sizeof(struct gotr_hash_code);
	const size_t enclen = len - sizeof(hmac);

	if (!room || !packed_msg || len != len_should)
		return 0;

	gotr_eprintf("parsing %s from %s", msgtype, user->closure);

	gotr_hmac(&user->our_hmac_key, enc, enclen, &hmac);
	if (0 != memcmp(&hmac, packed_msg, sizeof(hmac))) {
		gotr_eprintf("hmac mismatch");
		return 0;
	}

	if (gotr_symmetric_decrypt(enc, enclen, &user->our_sym_key,
	                           &user->our_sym_iv, enc) != enclen) {
		gotr_eprintf("could not decrypt msg");
		return 0;
	}
	return 1;
}

unsigned char *gotr_pack_pair_channel_init(const struct gotr_roomdata *room,
										   struct gotr_user *user,
										   size_t *len)
{
	struct msg_pair_channel_init *msg;

	if (!check_params_create_msg(room, user, (void*)&msg, sizeof(*msg), "pair_channel_init"))
		return NULL;


	gotr_ecdhe_key_get_public(&user->my_dhe_skey, &msg->sender_dhe_pkey);

	user->next_sending_msgtype = GOTR_PAIR_CHAN_ESTABLISH;
	*len = sizeof(*msg);
	return (unsigned char *)msg;
}

unsigned char *gotr_pack_pair_channel_est(const struct gotr_roomdata *room,
										  struct gotr_user *user,
										  size_t *len)
{
	struct msg_pair_channel_est *msg;
	struct gotr_dhe_pkey own_pub;

	if (!check_params_create_msg(room, user, (void*)&msg, sizeof(*msg), "pair_channel_est"))
		return NULL;

	gotr_ecdhe_key_get_public(&user->my_dhe_skey, &own_pub);
	if(!gotr_eddsa_sign(&room->my_dsa_skey, &own_pub, sizeof(own_pub), &msg->enc.sig_sender_dhe_pkey)) {
		gotr_eprintf("could not sign pair channel establishment message.");
		return NULL;
	}
	memcpy(&msg->enc.sender_dsa_pkey, &room->my_dsa_pkey, sizeof(room->my_dsa_pkey));

	return encrypt_and_hmac(user, (unsigned char *)msg, sizeof(*msg), len, GOTR_FLAKE_z);
}

unsigned char *gotr_pack_flake_z(const struct gotr_roomdata *room,
								 struct gotr_user *user,
								 size_t *len)
{
	struct msg_flake_z *msg;
	if (!check_params_create_msg(room, user, (void*)&msg, sizeof(*msg), "flake_z"))
		return NULL;

	serialize_point(msg->enc.sender_z[0].data, sizeof(msg->enc.sender_z[0].data), user->my_z[0]);
	serialize_point(msg->enc.sender_z[1].data, sizeof(msg->enc.sender_z[1].data), user->my_z[1]);

	return encrypt_and_hmac(user, (unsigned char *)msg, sizeof(*msg), len, GOTR_FLAKE_R);
}

unsigned char *gotr_pack_flake_R(const struct gotr_roomdata *room,
								 struct gotr_user *user,
								 size_t *len)
{
	struct msg_flake_R *msg;
	if (!check_params_create_msg(room, user, (void*)&msg, sizeof(*msg), "flake_R"))
		return NULL;

	serialize_point(msg->enc.sender_R[0].data, sizeof(msg->enc.sender_R[0].data), user->my_X[0]);
	serialize_point(msg->enc.sender_R[1].data, sizeof(msg->enc.sender_R[1].data), user->my_X[1]);

	return encrypt_and_hmac(user, (unsigned char *)msg, sizeof(*msg), len, GOTR_MSG);
}

unsigned char *gotr_pack_msg(const struct gotr_roomdata *room,
							 char *msg,
							 size_t *len)
{
	return NULL;
}

int gotr_parse_pair_channel_init(struct gotr_roomdata *room,
								 struct gotr_user *user,
								 unsigned char *packed_msg,
								 size_t len)
{
	struct msg_pair_channel_init *msg = (struct msg_pair_channel_init*)packed_msg;
	struct gotr_hash_code exchanged_key;

	gotr_eprintf("parsing pair_channel_init from %s", user->closure);

	if(!room || !packed_msg || len != sizeof(*msg))
		return 0;

	memcpy(&user->his_dhe_pkey, &msg->sender_dhe_pkey, sizeof(user->his_dhe_pkey));

	if(!gotr_ecdhe(&user->my_dhe_skey, &user->his_dhe_pkey, &exchanged_key)) {
		gotr_eprintf("ecdhe failed.");
		return 0;
	}
	gotr_sym_derive_key(&exchanged_key, &user->our_sym_key, &user->our_sym_iv);
	gotr_hmac_derive_key(&user->our_hmac_key, &user->our_sym_key,
	                     &exchanged_key, sizeof(exchanged_key), NULL);

	user->next_expected_msgtype = GOTR_PAIR_CHAN_ESTABLISH;
	return GOTR_OK;
}

int gotr_parse_pair_channel_est(struct gotr_roomdata *room,
								struct gotr_user *user,
								unsigned char *packed_msg,
								size_t len)
{
	struct msg_pair_channel_est *msg = (struct msg_pair_channel_est*)packed_msg;
	if(!check_hmac_decrypt(room, user, packed_msg, len, sizeof(*msg), "pair_channel_est"))
		return 0;

	memcpy(&user->his_dsa_pkey, &msg->enc.sender_dsa_pkey, sizeof(user->his_dsa_pkey));
	if (!gotr_eddsa_verify(&user->his_dsa_pkey, &user->his_dhe_pkey, sizeof(user->his_dhe_pkey), &msg->enc.sig_sender_dhe_pkey)) {
		gotr_eprintf("signature mismatch");
		return 0;
	}
	/// @todo: check pubkey trust level

	gotr_ecbd_gen_keypair(&user->my_r[0], &user->my_z[0]);
	gotr_ecbd_gen_keypair(&user->my_r[1], &user->my_z[1]);

	user->next_expected_msgtype = GOTR_FLAKE_z;
	return GOTR_OK;
}

int gotr_parse_flake_z(struct gotr_roomdata *room,
					   struct gotr_user *user,
					   unsigned char *packed_msg,
					   size_t len)
{
	struct msg_flake_z *msg = (struct msg_flake_z*)packed_msg;
	if(!check_hmac_decrypt(room, user, packed_msg, len, sizeof(*msg), "flake_z"))
		return 0;

	user->his_z[0] = deserialize_point((unsigned char*)&msg->enc.sender_z[0], sizeof(msg->enc.sender_z[0]));
	user->his_z[1] = deserialize_point((unsigned char*)&msg->enc.sender_z[1], sizeof(msg->enc.sender_z[1]));

	gotr_ecbd_gen_X_value(&user->my_X[0], user->his_z[1], user->my_z[1], user->my_r[0]);
	gotr_ecbd_gen_X_value(&user->my_X[1], user->his_z[0], user->my_z[0], user->my_r[1]);

	user->next_expected_msgtype = GOTR_FLAKE_R;
	return GOTR_OK;
}

int gotr_parse_flake_R(struct gotr_roomdata *room,
					   struct gotr_user *user,
					   unsigned char *packed_msg,
					   size_t len)
{
	struct msg_flake_R *msg = (struct msg_flake_R*)packed_msg;
	if(!check_hmac_decrypt(room, user, packed_msg, len, sizeof(*msg), "flake_R"))
		return 0;

	user->his_X[0] = deserialize_point((unsigned char*)&msg->enc.sender_R[0], sizeof(msg->enc.sender_R[0]));
	user->his_X[1] = deserialize_point((unsigned char*)&msg->enc.sender_R[1], sizeof(msg->enc.sender_R[1]));

	///@todo flake key

	user->next_expected_msgtype = GOTR_MSG;
	return GOTR_OK;
}

int gotr_parse_msg(struct gotr_roomdata *room, char *packed_msg, size_t len)
{
	gotr_eprintf("got \"anonymous\" massage: %s", ++packed_msg);
	return GOTR_OK;
}
