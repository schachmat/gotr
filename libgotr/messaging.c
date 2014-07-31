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

	if(!room || !user || !(msg = malloc(sizeof(struct msg_pair_channel_init))))
		return NULL;

	memset(msg, 0, sizeof(struct msg_pair_channel_init));

	gotr_ecdhe_key_create(&user->my_dhe_skey);
	gotr_ecdhe_key_get_public(&user->my_dhe_skey, &msg->sender_dhe_pkey);

	user->next_msgtype = GOTR_SEND_PAIR_CHAN_ESTABLISH;
	*len = sizeof(struct msg_pair_channel_init);
	return (unsigned char *)msg;
}

unsigned char *gotr_pack_pair_channel_est(const struct gotr_roomdata *room, struct gotr_user *user, size_t *len)
{
	struct msg_pair_channel_est *msg;
	struct gotr_dhe_pkey own_pub;
	struct gotr_hash_code key_material;

	if(!room || !user || !(msg = malloc(sizeof(struct msg_pair_channel_est))))
		return NULL;

	memset(msg, 0, sizeof(struct msg_pair_channel_est));

	if(!gotr_ecdhe(&user->my_dhe_skey, &user->his_dhe_pkey, &key_material)) {
		gotr_eprintf("ecdhe failed.");
		return NULL;
	}
	/// @todo derive key material for hmac and symmetric enc

	gotr_ecdhe_key_get_public(&user->my_dhe_skey, &own_pub);
	if(!gotr_eddsa_sign(&room->my_dsa_skey, &own_pub, sizeof(struct gotr_dhe_pkey), &msg->enc.sig_sender_dhe_pkey)) {
		gotr_eprintf("could not sign pair channel establishment message.");
		return NULL;
	}
	memcpy(&msg->enc.sender_dsa_pkey, &room->my_dsa_pkey, sizeof(struct gotr_dsa_pkey));

	/// @todo encrypt msg->enc and then build hmac(msg->enc) into msg->hmac

	user->next_msgtype = GOTR_SEND_FLAKE_z;
	*len = sizeof(struct msg_pair_channel_est);
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

	if(!room || !user || !packed_msg || len != sizeof(struct msg_pair_channel_init))
		return 0;

	memcpy(&user->his_dhe_pkey, &msg->sender_dhe_pkey, sizeof(struct gotr_dhe_pkey));

	user->expected_msgtype = GOTR_EXPECT_PAIR_CHAN_ESTABLISH;
	return GOTR_OK;
}

int gotr_parse_pair_channel_est(struct gotr_roomdata *room, struct gotr_user *user, char *packed_msg, size_t len)
{
	struct msg_pair_channel_est *msg = (struct msg_pair_channel_est*)packed_msg;

	if(!room || !user || !packed_msg || len != sizeof(struct msg_pair_channel_est))
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
