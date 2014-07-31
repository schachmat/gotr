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
	int bla;
};

unsigned char *gotr_pack_pair_channel_init(const struct gotr_roomdata *room, struct gotr_user *user, size_t *len)
{
	struct msg_pair_channel_init *msg;

	if(!room || !user || !(msg = malloc(sizeof(*msg))))
		return NULL;

	memset(msg, 0, sizeof(*msg));

	gotr_ecdhe_key_get_public(&user->my_dhe_skey, &msg->sender_dhe_pkey);

	user->next_msgtype = GOTR_SEND_PAIR_CHAN_ESTABLISH;
	*len = sizeof(*msg);
	return (unsigned char *)msg;
}

unsigned char *gotr_pack_pair_channel_est(const struct gotr_roomdata *room, struct gotr_user *user, size_t *len)
{
	struct msg_pair_channel_est *msg;
	struct gotr_dhe_pkey own_pub;

	if(!room || !user || !(msg = malloc(sizeof(*msg))))
		return NULL;

	memset(msg, 0, sizeof(*msg));

	gotr_ecdhe_key_get_public(&user->my_dhe_skey, &own_pub);
	if(!gotr_eddsa_sign(&room->my_dsa_skey, &own_pub, sizeof(own_pub), &msg->enc.sig_sender_dhe_pkey)) {
		gotr_eprintf("could not sign pair channel establishment message.");
		return NULL;
	}
	memcpy(&msg->enc.sender_dsa_pkey, &room->my_dsa_pkey, sizeof(room->my_dsa_pkey));

	gotr_symmetric_encrypt(&msg->enc, sizeof(msg->enc), &user->our_sym_key, &user->our_sym_iv, &msg->enc);
	gotr_hmac(&user->our_hmac_key, &msg->enc, sizeof(msg->enc), &msg->hmac);

	user->next_msgtype = GOTR_SEND_FLAKE_z;
	*len = sizeof(*msg);
	return (unsigned char *)msg;
}

unsigned char *gotr_pack_flake_z(const struct gotr_roomdata *room, struct gotr_user *user, size_t *len)
{
	return NULL;
}

unsigned char *gotr_pack_flake_R(const struct gotr_roomdata *room, struct gotr_user *user, size_t *len)
{
	return NULL;
}

unsigned char *gotr_pack_flake_validation(const struct gotr_roomdata *room, struct gotr_user *user, size_t *len)
{
	return NULL;
}

unsigned char *gotr_pack_msg(const struct gotr_roomdata *room, char *msg, size_t *len)
{
	return NULL;
}

int gotr_parse_pair_channel_init(struct gotr_roomdata *room, struct gotr_user *user, char *packed_msg, size_t len)
{
	struct msg_pair_channel_init *msg = (struct msg_pair_channel_init*)packed_msg;
	struct gotr_hash_code exchanged_key;

	if(!room || !user || !packed_msg || len != sizeof(*msg))
		return 0;

	memcpy(&user->his_dhe_pkey, &msg->sender_dhe_pkey, sizeof(msg->sender_dhe_pkey));

	if(!gotr_ecdhe(&user->my_dhe_skey, &user->his_dhe_pkey, &exchanged_key)) {
		gotr_eprintf("ecdhe failed.");
		return 0;
	}
	gotr_sym_derive_key(&exchanged_key, &user->our_sym_key, &user->our_sym_iv);
	gotr_hmac_derive_key(&user->our_hmac_key, &user->our_sym_key,
	                     &exchanged_key, sizeof(exchanged_key), NULL);

	user->expected_msgtype = GOTR_EXPECT_PAIR_CHAN_ESTABLISH;
	return GOTR_OK;
}

int gotr_parse_pair_channel_est(struct gotr_roomdata *room, struct gotr_user *user, char *packed_msg, size_t len)
{
	struct msg_pair_channel_est *msg = (struct msg_pair_channel_est*)packed_msg;

	if(!room || !user || !packed_msg || len != sizeof(*msg))
		return 0;

	/// @todo check hmac, decrypt, copy eddsa pubkey, check sig
	
	return GOTR_OK;
}

int gotr_parse_flake_y(struct gotr_roomdata *room, struct gotr_user *user, char *packed_msg, size_t len)
{
	return GOTR_OK;
}

int gotr_parse_flake_V(struct gotr_roomdata *room, struct gotr_user *user, char *packed_msg, size_t len)
{
	return GOTR_OK;
}

int gotr_parse_flake_validation(struct gotr_roomdata *room, struct gotr_user *user, char *packed_msg, size_t len)
{
	return GOTR_OK;
}

int gotr_parse_msg(struct gotr_roomdata *room, char *packed_msg, size_t len)
{
	gotr_eprintf("got \"anonymous\" massage: %s", ++packed_msg);
	return GOTR_OK;
}
