#include <stdio.h>

#include "util.h"
#include "crypto.h"
#include "gotr.h"
#include "messaging.h"
#include "b64.h"
#include "gka.h"
#include "key.h"

struct gotr_user;

struct gotr_chatroom {
	struct gotr_roomdata data;
	gotr_cb_send_all send_all;       ///< callback to send a message to every participant in this room
	gotr_cb_send_user send_user;       ///< callback to send a message to a specific user
	gotr_cb_receive_user receive_user; ///< callback to notify the client about a decrypted message he has to print
};

static struct gotr_user *gotr_init_user(struct gotr_chatroom *room, const void *user_closure);
static int (*handler_in[GOTR_MAX_EXPECTS])(struct gotr_roomdata *room, struct gotr_user *user, unsigned char *packed_msg, size_t len) = {
	[GOTR_EXPECT_PAIR_CHAN_INIT]      = gotr_parse_pair_channel_init,
	[GOTR_EXPECT_PAIR_CHAN_ESTABLISH] = gotr_parse_pair_channel_est,
	[GOTR_EXPECT_FLAKE_y]             = gotr_parse_flake_y,
	[GOTR_EXPECT_FLAKE_V]             = gotr_parse_flake_V,
	[GOTR_EXPECT_FLAKE_VALIDATE]      = gotr_parse_flake_validation,
};
static unsigned char *(*handler_out[GOTR_MAX_SENDS])(const struct gotr_roomdata *room, struct gotr_user *user, size_t *len) = {
	[GOTR_SEND_PAIR_CHAN_INIT]      = gotr_pack_pair_channel_init,
	[GOTR_SEND_PAIR_CHAN_ESTABLISH] = gotr_pack_pair_channel_est,
	[GOTR_SEND_FLAKE_z]             = gotr_pack_flake_z,
	[GOTR_SEND_FLAKE_R]             = gotr_pack_flake_R,
	[GOTR_SEND_FLAKE_VALIDATE]      = gotr_pack_flake_validation,
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

	/* ecc is slow otherwise */
	if ((err = gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0)))
		gotr_eprintf("failed to set libgcrypt option ENABLE_QUICK_RANDOM: %s",
				gcry_strerror(err));

	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	gotr_rand_poll();

	return gotr_gka_init();
}

struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_user send_user, gotr_cb_receive_user receive_user, const void *room_closure, const char *privkey_filename)
{
	struct gotr_chatroom *room;

	room = malloc(sizeof(struct gotr_chatroom));
	room->data.closure = room_closure;
	room->send_all = send_all;
	room->send_user = send_user;
	room->receive_user = receive_user;

	load_privkey(privkey_filename, &room->data.my_dsa_skey);
	gotr_eddsa_key_get_public(&room->data.my_dsa_skey, &room->data.my_dsa_pkey);
	return room;
}

int gotr_send(struct gotr_chatroom *room, char *plain_msg)
{
	char *b64_msg;
	int ret = 0;

	if(!(b64_msg = gotr_b64_enc((unsigned char *)plain_msg, strlen(plain_msg)))) {
		gotr_eprintf("unable to base64 encode message");
		return 0;
	}

	if(!(ret = room->send_all((void *)room->data.closure, b64_msg)))
		gotr_eprintf("unable to broadcast message");

	free(b64_msg);
	return ret;
}

int gotr_receive(struct gotr_chatroom *room, char *b64_msg)
{
	size_t len = 0;
	char *packed_msg = NULL;

	if (!room || !b64_msg) {
		gotr_eprintf("called gotr_receive with NULL argument");
		return 0;
	}

	if ((gotr_b64_dec(b64_msg, (unsigned char **)&packed_msg, &len))) {
		gotr_eprintf("could not decode message: %s", b64_msg);
		return 0;
	}
	packed_msg[len-1] = '\0';

	gotr_parse_msg(&room->data, packed_msg, len);

	free(packed_msg);
	return 1;
}

struct gotr_user *gotr_receive_user(struct gotr_chatroom *room, struct gotr_user *user, const void *user_closure, const char *b64_msg_in)
{
	struct gotr_user *u;
	size_t len = 0;
	unsigned char *packed_msg_in = NULL;
	unsigned char *packed_msg_out = NULL;
	char *b64_msg_out = NULL;
	size_t len_p = 0;

	if (!room || !b64_msg_in) {
		gotr_eprintf("called gotr_receive_user with NULL argument");
		return NULL;
	}

	if (!(u = user) && !(u = gotr_init_user(room, user_closure)))
		return NULL;

	if (0 != gotr_b64_dec(b64_msg_in, &packed_msg_in, &len)) {
		gotr_eprintf("could not decode message: %s", b64_msg_in);
		return NULL;
	}

	if (!handler_in[u->expected_msgtype] ||
			!handler_in[u->expected_msgtype](&room->data, u, packed_msg_in, len))
		gotr_eprintf("could not unpack message");
	free(packed_msg_in);

	if (!handler_out[u->next_msgtype] ||
	    !(packed_msg_out = handler_out[u->next_msgtype](&room->data, u, &len_p))) {
		gotr_eprintf("could not pack message");
		return u;
	}

	if((b64_msg_out = gotr_b64_enc(packed_msg_out, len_p))) {
		room->send_user((void *)room->data.closure, (void *)u->closure, b64_msg_out);
		free(b64_msg_out);
	} else {
		gotr_eprintf("could not b64 encode message");
	}
	free(packed_msg_out);

	return u;
}

/**
 * @brief BLABLA
 * @todo docu
 */
struct gotr_user *gotr_user_joined(struct gotr_chatroom *room, const void *user_closure)
{
	unsigned char *packed_msg;
	size_t len_p = 0;
	char *b64_msg;
	struct gotr_user *user;

	if(!room) {
		gotr_eprintf("passed room was NULL");
		return NULL;
	}

	if(!(user = gotr_init_user(room, user_closure))) {
		gotr_eprintf("could not create new user");
		return NULL;
	}

	if(!(packed_msg = gotr_pack_pair_channel_init(&room->data, user, &len_p))) {
		gotr_eprintf("could not pack msg_pair_channel_init message");
		return NULL;
	}

	if((b64_msg = gotr_b64_enc(packed_msg, len_p))) {
		room->send_user((void *)room->data.closure, (void *)user->closure, b64_msg);
		free(b64_msg);
	} else {
		gotr_eprintf("could not b64 encode msg_pair_channel_init message");
	}

	free(packed_msg);
	return user;
}

void gotr_user_left(struct gotr_chatroom *room, struct gotr_user *user)
{
	struct gotr_user *cur = room->data.users;

	if (cur == user) {
		gotr_ecdhe_key_clear(&cur->my_dhe_skey);
		room->data.users = cur->next;
		free(cur);
		return;
	}

	for (; cur; cur = cur->next)
		if (cur->next == user) {
			cur->next = user->next;
			gotr_ecdhe_key_clear(&user->my_dhe_skey);
			free(user);
		}
}

struct gotr_user *gotr_init_user(struct gotr_chatroom *room, const void *user_closure)
{
	struct gotr_user *user;

	if (!room || !(user = malloc(sizeof(struct gotr_user))))
		return NULL;

	gotr_ecdhe_key_create(&user->my_dhe_skey);

	user->closure = user_closure;
	user->expected_msgtype = GOTR_EXPECT_PAIR_CHAN_INIT;
	user->next_msgtype = GOTR_SEND_PAIR_CHAN_INIT;
	user->next = room->data.users;
	return room->data.users = user;
}

void gotr_leave(struct gotr_chatroom *room)
{
	struct gotr_user *user;

	if (!room)
		return;

	while (room->data.users) {
		user = room->data.users;
		room->data.users = user->next;
		free(user);
	}

	gotr_eddsa_key_clear(&room->data.my_dsa_skey);

	free(room);
}
