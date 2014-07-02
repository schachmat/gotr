#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <gcrypt.h>
#include <arpa/inet.h>

#include "util.h"
#include "crypto.h"
#include "libgotr.h"
#include "b64.h"
#include "bdgka.h"

unsigned char *gotr_pack_est_pair_channel(const struct gotr_chatroom *room, struct gotr_user *user)
{
	struct est_pair_channel *msg;

	if(!room || !user || !(msg = malloc(sizeof(struct est_pair_channel))))
		return NULL;

	memset(msg, 0, sizeof(struct est_pair_channel));

	msg->op = htonl(GOTR_OP_EST_PAIR_CHANNEL);

	memcpy(&msg->sender_pub, &room->my_pubkey, sizeof(room->my_pubkey));

	gotr_ecdhe_key_create(&user->dhe_privkey);
	gotr_ecdhe_key_get_public(&user->dhe_privkey, &user->dhe_pubkey);
	memcpy(&msg->dh_pub, &user->dhe_pubkey, sizeof(user->dhe_pubkey));

	if(!gotr_eddsa_sign(&room->my_privkey, msg, sizeof(struct est_pair_channel), &msg->sig)) {
		gotr_eprintf("could not sign est_pair_channel message");
		free(msg);
		return NULL;
	}

	return (unsigned char *)msg;
}

unsigned char *gotr_pack_flake_z(const struct gotr_chatroom *room, struct gotr_user *user)
{
	return NULL;
}

unsigned char *gotr_pack_flake_R(const struct gotr_chatroom *room, struct gotr_user *user)
{
	return NULL;
}

unsigned char *gotr_pack_flake_validation(const struct gotr_chatroom *room, struct gotr_user *user)
{
	return NULL;
}

unsigned char *gotr_pack_msg(const struct gotr_chatroom *room, char *msg)
{
	return NULL;
}

int gotr_parse_est_pair_channel(struct gotr_chatroom *room, char *packed_msg)
{
	return GOTR_OK;
}

int gotr_parse_flake_y(struct gotr_chatroom *room, char *packed_msg)
{
	return GOTR_OK;
}

int gotr_parse_flake_V(struct gotr_chatroom *room, char *packed_msg)
{
	return GOTR_OK;
}

int gotr_parse_flake_validation(struct gotr_chatroom *room, char *packed_msg)
{
	return GOTR_OK;
}

int gotr_parse_msg(struct gotr_chatroom *room, char *packed_msg)
{
	gotr_eprintf("got \"anonymous\" massage: %s", ++packed_msg);
	return GOTR_OK;
}
