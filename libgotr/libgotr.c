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

#define GOTR_OP_EST_PAIR_CHANNEL ((unsigned char)0)
#define GOTR_OP_FLAKE_SEND_z     ((unsigned char)1)
#define GOTR_OP_FLAKE_SEND_R     ((unsigned char)2)
#define GOTR_OP_FLAKE_VALIDATE   ((unsigned char)3)
#define GOTR_OP_MSG              ((unsigned char)4)
#define GOTR_OP_MAX              ((unsigned char)5)

static struct gotr_user *gotr_new_user(struct gotr_chatroom *room, char *name);

static int gotr_parse_est_pair_channel(struct gotr_chatroom *room, char *msg);
static int gotr_parse_flake_y         (struct gotr_chatroom *room, char *msg);
static int gotr_parse_flake_V         (struct gotr_chatroom *room, char *msg);
static int gotr_parse_flake_validation(struct gotr_chatroom *room, char *msg);
static int gotr_parse_msg             (struct gotr_chatroom *room, char *msg);
static int gotr_pack_est_pair_channel(struct gotr_chatroom *room, char *msg);
static int gotr_pack_flake_z         (struct gotr_chatroom *room, char *msg);
static int gotr_pack_flake_R         (struct gotr_chatroom *room, char *msg);
static int gotr_pack_flake_validation(struct gotr_chatroom *room, char *msg);
static int gotr_pack_msg             (struct gotr_chatroom *room, char *msg);

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

struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr, gotr_cb_receive_usr receive_usr)
{
	struct gotr_chatroom *room;

	room = malloc(sizeof(struct gotr_chatroom));
	room->send_all = send_all;
	room->send_usr = send_usr;
	room->receive_usr = receive_usr;
	
	gotr_eprintf("generating keypair, please wait...");
	gotr_eddsa_key_create(&room->my_priv_key);
	gotr_eddsa_key_get_public(&room->my_priv_key, &room->my_pub_key);
	gotr_eprintf("done generating keypair.");

	return room;
}

int gotr_send(struct gotr_chatroom *room, char *message)
{
	size_t len = strlen(message);
	unsigned char *buf = malloc(len+2);
	char *msg;
	int ret = 0;

	if (snprintf((char *)buf, len+2, "%c%s", GOTR_OP_MSG, message) != len+1) {
		gotr_eprintf("snprintf failed with wrong message length");
		goto fail;
	}

	if(!(msg = otrl_base64_otr_encode(buf, len+1))) {
		gotr_eprintf("unable to base64 encode message");
		goto fail;
	}

	if(!(ret = room->send_all(room, msg)))
		gotr_eprintf("unable to broadcast message");

	free(msg);
fail:
	free(buf);
	return ret;
}

static int gotr_parse_est_pair_channel(struct gotr_chatroom *room, char *msg)
{
	return 1;
}

static int gotr_parse_flake_y(struct gotr_chatroom *room, char *msg)
{
	return 1;
}

static int gotr_parse_flake_V(struct gotr_chatroom *room, char *msg)
{
	return 1;
}

static int gotr_parse_flake_validation(struct gotr_chatroom *room, char *msg)
{
	return 1;
}

static int gotr_parse_msg(struct gotr_chatroom *room, char *msg)
{
	gotr_eprintf("got \"anonymous\" massage: %s", ++msg);
	return 1;
}

int gotr_receive(struct gotr_chatroom *room, char *message)
{
	size_t len = 0;
	char *msg = NULL;
	uint8_t op;

	if (!room || !message) {
		gotr_eprintf("called gotr_receive with NULL argument");
		return 0;
	}

	if ((otrl_base64_otr_decode(message, (unsigned char **)&msg, &len))) {
		gotr_eprintf("could not decode message: %s", message);
		return 0;
	}
	msg[len-1] = '\0';

	op = *msg;

	if (op >= 0 && op < GOTR_OP_MAX && msg_handler[op])
		msg_handler[op](room, msg);

	free(msg);
	return 1;
}

/**
 * @brief BLABLA
 * @todo error checking, docu, extract message packing
 */
void gotr_user_joined(struct gotr_chatroom *room, char *name) {
	int err;
	struct gotr_user *user;
	unsigned char *message;
	size_t message_size;
	struct gotr_EcdhePublicKey *message_dhe_pub_key;
	struct gotr_EddsaSignature *message_signature;
	struct gotr_eddsa_public_key *message_dsa_pub_key;
	char *b64_message;

	user = gotr_new_user(room, name);

	message_size = sizeof(unsigned char)        // op
		+ sizeof(struct gotr_EcdhePublicKey)    // DH public key
		+ sizeof(struct gotr_EddsaSignature)    // signature
		+ sizeof(struct gotr_eddsa_public_key); // public key for signature
	gotr_eprintf("msgsiz: %d", (int)message_size);
	message = malloc(message_size);

	*message = GOTR_OP_EST_PAIR_CHANNEL;

	gotr_ecdhe_key_create(&user->dhe_privkey);
	message_dhe_pub_key = (struct gotr_EcdhePublicKey *)(message + 1);
	gotr_ecdhe_key_get_public(&user->dhe_privkey, message_dhe_pub_key);

	message_signature = (struct gotr_EddsaSignature *)(message_dhe_pub_key + 1);
	err = gotr_eddsa_sign(&room->my_priv_key, message, sizeof(unsigned char) + sizeof(struct gotr_EcdhePublicKey), message_signature);

	message_dsa_pub_key = (struct gotr_eddsa_public_key *)(message_signature + 1);
	memcpy(message_dsa_pub_key, &room->my_pub_key, sizeof(struct gotr_EcdhePublicKey));

	b64_message = otrl_base64_otr_encode(message, message_size);

	room->send_usr(room, user, b64_message);

	free(b64_message);
	free(message);
}

struct gotr_user *gotr_new_user(struct gotr_chatroom *room, char *name)
{
	struct gotr_user *user;

	if (!room || !(user = malloc(sizeof(struct gotr_user))))
		return NULL;

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

	gotr_eddsa_key_clear(&room->my_priv_key);

	free(room);
}
