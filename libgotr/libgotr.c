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

#define GOTR_PROT_VERSION "1"
#define GOTR_GCRYPT_VERSION "1.6.1"

enum {
	GOTR_OP_EST_PAIR_CHANNEL = 0,
	GOTR_OP_FLAKE_SEND_z = 1,
	GOTR_OP_FLAKE_SEND_R = 2,
	GOTR_OP_FLAKE_VALIDATE = 3,
	GOTR_OP_MSG = 4,
	GOTR_OP_MAX = 5
};

static struct gotr_user *gotr_new_user(struct gotr_chatroom *room, void *user_data);

/// @todo move to messaging.[ch]
static unsigned char *gotr_pack_est_pair_channel(const struct gotr_chatroom *room, struct gotr_user *user);
static unsigned char *gotr_pack_flake_z         (const struct gotr_chatroom *room, struct gotr_user *user);
static unsigned char *gotr_pack_flake_R         (const struct gotr_chatroom *room, struct gotr_user *user);
static unsigned char *gotr_pack_flake_validation(const struct gotr_chatroom *room, struct gotr_user *user);
static unsigned char *gotr_pack_msg             (const struct gotr_chatroom *room, char *msg);
static int gotr_parse_est_pair_channel(struct gotr_chatroom *room, char *packed_msg);
static int gotr_parse_flake_y         (struct gotr_chatroom *room, char *packed_msg);
static int gotr_parse_flake_V         (struct gotr_chatroom *room, char *packed_msg);
static int gotr_parse_flake_validation(struct gotr_chatroom *room, char *packed_msg);
static int gotr_parse_msg             (struct gotr_chatroom *room, char *packed_msg);

static int (*msg_handler[GOTR_OP_MAX])(struct gotr_chatroom *, char *) = {
	[GOTR_OP_EST_PAIR_CHANNEL] = &gotr_parse_est_pair_channel,
	[GOTR_OP_FLAKE_SEND_z] = &gotr_parse_flake_y,
	[GOTR_OP_FLAKE_SEND_R] = &gotr_parse_flake_V,
	[GOTR_OP_FLAKE_VALIDATE] = &gotr_parse_flake_validation,
	[GOTR_OP_MSG] = &gotr_parse_msg,
};

int gotr_init()
{
	gcry_error_t err = 0;
	if (!gcry_check_version(GOTR_GCRYPT_VERSION)) {
		gotr_eprintf("libgcrypt version mismatch");
		return 0;
	}

	if ((err = gcry_control(GCRYCTL_DISABLE_SECMEM, 0)))
		gotr_eprintf("failed to set libgcrypt option DISABLE_SECMEM: %s",
				gcry_strerror(err));

	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	gotr_rand_poll();

	return gotr_bdgka_init();
}

struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr, gotr_cb_receive_usr receive_usr, void *room_data)
{
	struct gotr_chatroom *room;

	room = malloc(sizeof(struct gotr_chatroom));
	room->data = room_data;
	room->send_all = send_all;
	room->send_usr = send_usr;
	room->receive_usr = receive_usr;
	
	gotr_eprintf("generating keypair, please wait...");
	gotr_eddsa_key_create(&room->my_privkey);
	gotr_eddsa_key_get_public(&room->my_privkey, &room->my_pubkey);
	gotr_eprintf("done generating keypair.");

	return room;
}

int gotr_send(struct gotr_chatroom *room, char *plain_msg)
{
	size_t len = strlen(plain_msg);
	unsigned char *packed_msg = malloc(len+2);
	char *b64_msg;
	int ret = 0;

	if (snprintf((char *)packed_msg, len+2, "%c%s", GOTR_OP_MSG, plain_msg) != len+1) {
		gotr_eprintf("snprintf failed with wrong message length");
		goto fail;
	}

	if(!(b64_msg = gotr_b64_enc(packed_msg, len+1))) {
		gotr_eprintf("unable to base64 encode message");
		goto fail;
	}

	if(!(ret = room->send_all(room, b64_msg)))
		gotr_eprintf("unable to broadcast message");

	free(b64_msg);
fail:
	free(packed_msg);
	return ret;
}

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

static int gotr_parse_est_pair_channel(struct gotr_chatroom *room, char *packed_msg)
{
	return GOTR_OK;
}

static int gotr_parse_flake_y(struct gotr_chatroom *room, char *packed_msg)
{
	return GOTR_OK;
}

static int gotr_parse_flake_V(struct gotr_chatroom *room, char *packed_msg)
{
	return GOTR_OK;
}

static int gotr_parse_flake_validation(struct gotr_chatroom *room, char *packed_msg)
{
	return GOTR_OK;
}

static int gotr_parse_msg(struct gotr_chatroom *room, char *packed_msg)
{
	gotr_eprintf("got \"anonymous\" massage: %s", ++packed_msg);
	return GOTR_OK;
}

int gotr_receive(struct gotr_chatroom *room, char *b64_msg)
{
	size_t len = 0;
	char *packed_msg = NULL;
	uint8_t op;

	if (!room || !b64_msg) {
		gotr_eprintf("called gotr_receive with NULL argument");
		return 0;
	}

	if ((gotr_b64_dec(b64_msg, (unsigned char **)&packed_msg, &len))) {
		gotr_eprintf("could not decode message: %s", b64_msg);
		return 0;
	}
	packed_msg[len-1] = '\0';

	op = *packed_msg;

	if (op >= 0 && op < GOTR_OP_MAX && msg_handler[op])
		msg_handler[op](room, packed_msg);

	free(packed_msg);
	return 1;
}

/**
 * @brief BLABLA
 * @todo docu
 */
void gotr_user_joined(struct gotr_chatroom *room, void *user_data) {
	unsigned char *packed_msg;
	char *b64_msg;
	struct gotr_user *user;

	if(!room) {
		gotr_eprintf("passed room was NULL");
		return;
	}

	if(!(user = gotr_new_user(room, user_data))) {
		gotr_eprintf("could not create new user");
		return;
	}

	if(!(packed_msg = gotr_pack_est_pair_channel(room, user))) {
		gotr_eprintf("could not pack est_pair_channel message");
		return;
	}

	if((b64_msg = gotr_b64_enc(packed_msg, sizeof(struct est_pair_channel)))) {
		room->send_usr(room, user, b64_msg);
		free(b64_msg);
	} else {
		gotr_eprintf("could not b64 encode est_pair_channel message");
	}

	free(packed_msg);
}

struct gotr_user *gotr_new_user(struct gotr_chatroom *room, void *user_data)
{
	struct gotr_user *user;

	if (!room || !(user = malloc(sizeof(struct gotr_user))))
		return NULL;

	user->data = user_data;
	user->state = GOTR_STATE_UNKNOWN;
	user->next = room->users;
	return room->users = user;
}

void gotr_leave(struct gotr_chatroom *room)
{
	struct gotr_user *user;

	if (!room)
		return;

	while (room->users != NULL) {
		user = room->users;
		room->users = user->next;
	}

	gotr_eddsa_key_clear(&room->my_privkey);

	free(room);
}
