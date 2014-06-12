#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <gcrypt.h>
#include <arpa/inet.h>

#define GOTR_PROT_VERSION "1"
#define GOTR_GCRYPT_VERSION "1.6.0"

#define GOTR_OP_INIT_PAIR_CHANNEL ((char)0)
#define GOTR_OP_FLAKE_SEND_z      ((char)1)
#define GOTR_OP_FLAKE_SEND_R      ((char)2)
#define GOTR_OP_FLAKE_VALIDATE    ((char)3)
#define GOTR_OP_MSG               ((char)4)
#define GOTR_OP_MAX               ((char)5)

#define GOTR_STATE_UNKNOWN             ((char)0)
#define GOTR_STATE_CHANNEL_ESTABLISHED ((char)1)
#define GOTR_STATE_FLAKE_GOT_y         ((char)2)
#define GOTR_STATE_FLAKE_GOT_V         ((char)3)
#define GOTR_STATE_FLAKE_VALIDATED     ((char)4)

#include "util.h"
#include "libgotr.h"
#include "b64.h"

static int gotr_got_msg(struct gotr_chatroom *room, char *msg);

static int (*msg_handler[GOTR_OP_MAX])(struct gotr_chatroom *, char *) = {
	[GOTR_OP_MSG] = &gotr_got_msg,
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

	return 1;
}

struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr, gotr_cb_receive_usr receive_usr)
{
	struct gotr_chatroom *room;

	room = malloc(sizeof(struct gotr_chatroom));
	room->send_all = send_all;
	room->send_usr = send_usr;
	room->receive_usr = receive_usr;

	return room;
}

void gotr_keyupdate(struct gotr_chatroom *room)
{
	
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

	if(!(ret = room->send_all(msg)))
		gotr_eprintf("unable to broadcast message");

	free(msg);
fail:
	free(buf);
	return ret;
}

static int gotr_got_msg(struct gotr_chatroom *room, char *msg)
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

	// header
	op = *msg;

	if (op >= 0 && op < GOTR_OP_MAX && msg_handler[op])
		msg_handler[op](room, msg);

	return 1;
}

void gotr_add_user(struct gotr_chatroom *room, char *pub_key)
{
	struct gotr_user *new_user;

	new_user = malloc(sizeof(struct gotr_user));
	new_user->next = room->users;
	room->users = new_user;
}

void gotr_leave(struct gotr_chatroom *room)
{
	struct gotr_user *user;

	while (room->users != NULL) {
		user = room->users;
		room->users = user->next;
		free(user);
	}

	free(room);
}

// User has to free() the returned pointer!
char* gotr_encode(const char *in, size_t len)
{
	char *tmp;
	char *ret = malloc(2*len + 1);
	if (!in || !ret)
		return NULL;

	for (tmp = ret; len--; tmp += 2)
		snprintf(tmp, 3, "%02X", *in++);

	return ret;
}

// User has to free() the returned pointer!
char* gotr_decode(const char *in, size_t* len)
{
	char *tmp;
	size_t n = strlen(in) / 2;
	char *ret;
	if (!in || !len || !n || !(ret = malloc(n+1)))
		return NULL;

	*len = n;
	for (tmp = ret; n--; in += 2)
		sscanf(in, "%2hhx%*s", (unsigned char*)(tmp++));

	ret[*len] = '\0';
	return ret;
}
