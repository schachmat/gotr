#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <gcrypt.h>
#include <arpa/inet.h>

#define GOTR_PROT_VERSION "1"
#define GOTR_GCRYPT_VERSION "1.6.0"

#include "util.h"
#include "libgotr.h"
#include "b64.h"

enum gotr_ops {
	GOTR_OP_IDLE = 0,
	GOTR_OP_MSG,
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

//	char setup_message[crypto_box_PUBLICKEYBYTES + 3];

//	crypto_box_keypair(room->pub_key, room->sec_key);
//	setup_message[0] = '/';
//	setup_message[crypto_box_PUBLICKEYBYTES + 1] = '\n';
//	setup_message[crypto_box_PUBLICKEYBYTES + 2] = '\0';
//	memcpy(room->pub_key, setup_message + 1, crypto_box_PUBLICKEYBYTES);

//	room->send_all(setup_message);

	return room;
}

void gotr_keyupdate(struct gotr_chatroom *room)
{
	
}

void gotr_send(struct gotr_chatroom *room, char *message)
{
	size_t len = strlen(message);
	char *msg = otrl_base64_otr_encode(message, len);
	room->send_all(msg);
	free(msg);
}

int gotr_receive(struct gotr_chatroom *room, char *message)
{
	size_t len = 0;
	char *msg = NULL;
	enum gotr_ops op;

	if (!room || !message) {
		gotr_eprintf("called gotr_receive with NULL argument");
		return 0;
	}

//	if (strstr(message, "?GOTR?") != message) {
//		gotr_eprintf("received unencrypted message: %s", message);
//		room->receive_usr(room, "!!!UNENCRYPTED!!!", message);
//		return 0;
//	}
//	message += 6;
//
//	if (*message != '1') {
//		gotr_eprintf("unsupported protocol version: %c", *message);
//		return 0;
//	}
//	message++;

	if ((otrl_base64_otr_decode(message, &msg, &len))) {
		gotr_eprintf("could not decode message: %s", message);
		return 0;
	}
	msg[len-1] = '\0';
	gotr_eprintf("got \"anonymous\" massage: %s", msg);

	// header
	op = ntohs(*((uint16_t*)msg));
	len -= 2;
	msg += 2;

	switch (op) {
	case GOTR_OP_IDLE:
		break;
	case GOTR_OP_MSG:
		room->receive_usr(room, "jemand", msg);
		break;
	default:
		break;
	}

	return 1;
}

void gotr_add_user(struct gotr_chatroom *room, char *pub_key)
{
	struct gotr_user *new_user;
	
	new_user = malloc(sizeof(struct gotr_user));
	new_user->next = room->users;
	room->users = new_user;
	
//	memcpy(new_user->pub_key, pub_key, crypto_box_PUBLICKEYBYTES);
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
