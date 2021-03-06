/* This file is part of libgotr.
 * (C) 2014-2015 Markus Teich, Jannik Theiß
 *
 * libgotr is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * libgotr is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libgotr; see the file LICENSE.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <stdio.h>

#include "b64.h"
#include "crypto.h"
#include "gka.h"
#include "gotr.h"
#include "key.h"
#include "messaging.h"
#include "user.h"
#include "util.h"

struct gotr_user;

struct gotr_chatroom {
	struct gotr_roomdata data;
	gotr_cb_send_all send_all;         ///< callback to send a message to every participant in this room
	gotr_cb_send_user send_user;       ///< callback to send a message to a specific user
	gotr_cb_receive_user receive_user; ///< callback to notify the client about a decrypted message he has to print
};

static struct gotr_user *gotr_init_user(struct gotr_chatroom *room, const void *user_closure);
static struct gotr_user *gotr_user_in_room(struct gotr_chatroom *room, struct gotr_user *user);
static int (*handler_in[GOTR_MAX_MSGTYPES])(struct gotr_roomdata *room, struct gotr_user *user, unsigned char *packed_msg, size_t len) = {
	[GOTR_PAIR_CHAN_INIT]      = gotr_parse_pair_channel_init,
	[GOTR_PAIR_CHAN_ESTABLISH] = gotr_parse_pair_channel_est,
	[GOTR_FLAKE_z]             = gotr_parse_flake_z,
	[GOTR_FLAKE_R]             = gotr_parse_flake_R,
	[GOTR_FLAKE_VALIDATE]      = gotr_parse_flake_validate,
};
static unsigned char *(*handler_out[GOTR_MAX_MSGTYPES])(struct gotr_roomdata *room, struct gotr_user *user, size_t *len) = {
	[GOTR_PAIR_CHAN_INIT]      = gotr_pack_pair_channel_init,
	[GOTR_PAIR_CHAN_ESTABLISH] = gotr_pack_pair_channel_est,
	[GOTR_FLAKE_z]             = gotr_pack_flake_z,
	[GOTR_FLAKE_R]             = gotr_pack_flake_R,
	[GOTR_FLAKE_VALIDATE]      = gotr_pack_flake_validate,
};

int gotr_init()
{
	gcry_error_t err = 0;
	if (!gcry_check_version(GOTR_GCRYPT_VERSION)) {
		gotr_eprintf("libgcrypt version mismatch");
		return 0;
	}

	if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
	{
		/* libgcrypt initialization not yet finished. Set some options. */

		/* SECMEM cannot be resized dynamically.
		 * We do not know how much we need */
		if ((err = gcry_control(GCRYCTL_DISABLE_SECMEM, 0)))
			gotr_eprintf("failed to set libgcrypt option DISABLE_SECMEM: %s",
			             gcry_strerror(err));

		/* ecc is slow otherwise. long term key generation should be done by the
		 * separate gotr_genkey binary, which does not set this option. */
		if ((err = gcry_control(GCRYCTL_ENABLE_QUICK_RANDOM, 0)))
			gotr_eprintf("failed to set libgcrypt option ENABLE_QUICK_RANDOM: %s",
			             gcry_strerror(err));

		gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	}
	gotr_rand_poll();
	gotr_gka_init();
	return 1;
}

struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_user send_user, gotr_cb_receive_user receive_user, const void *room_closure, const char *privkey_filename)
{
	struct gotr_chatroom *room;

	room = calloc(sizeof(*room), 1);
	room->data.closure = room_closure;
	room->send_all = send_all;
	room->send_user = send_user;
	room->receive_user = receive_user;

	if (privkey_filename &&
	    !load_privkey(privkey_filename, &room->data.my_longterm_skey)) {
		free(room);
		return NULL;
	} else {
		gotr_ecdhe_key_create(&room->data.my_longterm_skey);
	}

	gotr_ecdhe_key_get_public(&room->data.my_longterm_skey, &room->data.my_longterm_pkey);
	return room;
}

///TODO:remove type argument
static void pack_encode_send(struct gotr_chatroom* room, struct gotr_user* user, gotr_msgtype type)
{
	unsigned char *packed_msg;
	size_t len_p = 0;
	char *b64_msg;

	if (type == GOTR_MSG)
		return;

	if (!handler_out[type] ||
	    !(packed_msg = handler_out[type](&room->data, user, &len_p))) {
		gotr_eprintf("could not pack some msg");
		return;
	}

	if((b64_msg = gotr_b64_enc(packed_msg, len_p))) {
		room->send_user((void *)room->data.closure, (void *)user->closure, b64_msg);
		free(b64_msg);
	} else {
		gotr_eprintf("could not b64 encode some msg");
	}
	free(packed_msg);
}

void gotr_rekey(struct gotr_chatroom *room, struct gotr_user *user)
{
	struct gotr_user* cur = room->data.users;

	if (!room) {
		gotr_eprintf("rekey called with parameter room == NULL");
		return;
	}

	if (user) {
		if (!(cur = gotr_user_in_room(room, user))) {
			gotr_eprintf("rekey: user not in room");
			return;
		}
		gotr_ecdhe_key_clear(&user->my_dhe_skey);
		gotr_ecdhe_key_create(&user->my_dhe_skey);
		pack_encode_send(room, user, GOTR_PAIR_CHAN_INIT);
		user->next_expected_msgtype = GOTR_PAIR_CHAN_INIT;
	}

	for (; cur; cur = cur->next) {
		gotr_ecdhe_key_clear(&cur->my_dhe_skey);
		gotr_ecdhe_key_create(&cur->my_dhe_skey);
		pack_encode_send(room, cur, GOTR_PAIR_CHAN_INIT);
		cur->next_expected_msgtype = GOTR_PAIR_CHAN_INIT;
	}
}

enum gotr_state gotr_get_state(struct gotr_chatroom *room, struct gotr_user *user)
{
	struct gotr_user* cur;
	enum gotr_state ret = gotr_state_not_private;
	enum gotr_state ustate;

	if (!room) {
		gotr_eprintf("get_state called with parameter room == NULL");
		return gotr_state_not_private;
	}

	if (user) {
		if (!(cur = gotr_user_in_room(room, user))) {
			gotr_eprintf("rekey: user not in room");
			return gotr_state_not_private;
		}
		if (GOTR_PAIR_CHAN_ESTABLISH == cur->next_expected_msgtype)
			return gotr_state_stage0;
		if (GOTR_FLAKE_z == cur->next_expected_msgtype)
			return gotr_state_stage1;
		if (GOTR_FLAKE_R == cur->next_expected_msgtype)
			return gotr_state_stage2;
		if (GOTR_FLAKE_VALIDATE == cur->next_expected_msgtype)
			return gotr_state_stage3;
		if (GOTR_MSG == cur->next_expected_msgtype)
			return gotr_state_private;
		return gotr_state_not_private;
	}

	for (cur = room->data.users; cur; cur = cur->next) {
		if ((ustate = gotr_get_state(room, cur)) > gotr_state_not_private) {
			if (ustate < ret || gotr_state_not_private == ret)
				ret = ustate;
		}
	}
	return ret;
}

int gotr_send(struct gotr_chatroom *room, char *plain_msg)
{
	unsigned char *packed_msg_out = NULL;
	char *b64_msg_out = NULL;
	size_t len_packed = 0;
	int ret = 0;

	if (!(packed_msg_out = gotr_pack_msg(&room->data, plain_msg, &len_packed))) {
		gotr_eprintf("could not pack text message");
		return 0;
	}

	if ((b64_msg_out = gotr_b64_enc(packed_msg_out, len_packed))) {
		if (!(ret = room->send_all((void *)room->data.closure, b64_msg_out)))
			gotr_eprintf("unable to broadcast message");
		free(b64_msg_out);
	} else {
		gotr_eprintf("could not b64 encode message");
	}
	free(packed_msg_out);

	return ret;
}

int gotr_receive(struct gotr_chatroom *room, char *b64_msg)
{
	size_t len = 0;
	char *packed_msg = NULL;
	char *plain_msg = NULL;
	struct gotr_user* sender;

	if (!room || !b64_msg) {
		gotr_eprintf("called gotr_receive with NULL argument");
		return 0;
	}

	if (gotr_b64_dec(b64_msg, (unsigned char **)&packed_msg, &len)) {
		gotr_eprintf("could not decode message: %s", b64_msg);
		return 0;
	}

	if ((plain_msg = gotr_parse_msg(&room->data, packed_msg, len, &sender))) {
		room->receive_user((void*)room->data.closure, (void*)sender->closure,
						   plain_msg);
		free(plain_msg);
	} else {
		gotr_eprintf("could not decrypt text message");
	}

	free(packed_msg);
	return 1;
}

static struct gotr_user *gotr_user_in_room(struct gotr_chatroom *room, struct gotr_user *user)
{
	struct gotr_user* cur = room->data.users;

	while (cur && cur != user)
		cur = cur->next;
	return cur;
}

struct gotr_user *gotr_receive_user(struct gotr_chatroom *room, struct gotr_user *user, const void *user_closure, const char *b64_msg_in)
{
	struct gotr_user *u;
	size_t len = 0;
	unsigned char *packed_msg_in = NULL;

	if (!room || !b64_msg_in) {
		gotr_eprintf("called gotr_receive_user with NULL argument");
		return NULL;
	}
	if (user && !gotr_user_in_room(room, user)) {
		gotr_eprintf("gotr_receive_user: specified user is not in specified room");
		return NULL;
	}

	if (!(u = user) && !(u = gotr_init_user(room, user_closure))) {
		gotr_eprintf("could neither derive nor create user");
		return NULL;
	}

	if (0 != gotr_b64_dec(b64_msg_in, &packed_msg_in, &len)) {
		gotr_eprintf("could not decode message: %s", b64_msg_in);
		return NULL;
	}

	// rekey
	if (len == sizeof(struct msg_pair_channel_init) &&
		u->next_expected_msgtype != GOTR_PAIR_CHAN_INIT &&
		u->next_sending_msgtype != GOTR_PAIR_CHAN_INIT)
		u->next_expected_msgtype = u->next_sending_msgtype = GOTR_PAIR_CHAN_INIT;

	if (!handler_in[u->next_expected_msgtype] ||
	    !handler_in[u->next_expected_msgtype](&room->data, u, packed_msg_in, len)) {
		gotr_eprintf("could not unpack message");
		free(packed_msg_in);
		return u;
	}
	free(packed_msg_in);

	pack_encode_send(room, u, u->next_sending_msgtype);
	return u;
}

struct gotr_user *gotr_user_joined(struct gotr_chatroom *room, const void *user_closure)
{
	struct gotr_user *user;

	if(!room) {
		gotr_eprintf("passed room was NULL");
		return NULL;
	}

	if(!(user = gotr_init_user(room, user_closure))) {
		gotr_eprintf("could not create new user");
		return NULL;
	}

	pack_encode_send(room, user, GOTR_PAIR_CHAN_INIT);
	return user;
}

static void cleanup_user(struct gotr_user *user)
{
	gotr_ecdhe_key_clear(&user->my_dhe_skey);
/* members we do not have to clear:
	struct gotr_auth_key his_circle_auth;
	struct gotr_sym_key  his_circle_key;
	struct gotr_sym_iv   his_circle_iv;
	struct gotr_auth_key our_hmac_key;
	struct gotr_sym_key  our_sym_key;
	struct gotr_sym_iv   our_sym_iv;
	struct gotr_dhe_pkey his_dhe_pkey;
	struct gotr_dhe_pkey his_longterm_pkey;
*/
	gcry_mpi_release(user->my_r[0]);
	gcry_mpi_release(user->my_r[1]);
	gcry_mpi_point_release(user->my_z[0]);
	gcry_mpi_point_release(user->my_z[1]);
	gcry_mpi_point_release(user->his_z[0]);
	gcry_mpi_point_release(user->his_z[1]);
	gcry_mpi_point_release(user->my_X[0]);
	gcry_mpi_point_release(user->my_X[1]);
	gcry_mpi_point_release(user->his_X[0]);
	gcry_mpi_point_release(user->his_X[1]);
}

void gotr_user_left(struct gotr_chatroom *room, struct gotr_user *user)
{
	struct gotr_user *cur;
	struct gotr_user **next;

	if (!room || !user)
		return;

	room->data.circle_valid = 0;
	next = &(room->data.users);

	for (cur = room->data.users; cur; next = &(cur->next), cur = cur->next)
		if (cur == user) {
			*next = user->next;
			cleanup_user(user);
			free(user);
			return;
		}
}

struct gotr_user *gotr_init_user(struct gotr_chatroom *room, const void *user_closure)
{
	struct gotr_user *user;

	if (!room || !(user = calloc(sizeof(*user), 1)))
		return NULL;

	gotr_ecdhe_key_create(&user->my_dhe_skey);

	user->closure = user_closure;
	user->next_expected_msgtype = GOTR_PAIR_CHAN_INIT;
	user->next_sending_msgtype = GOTR_PAIR_CHAN_INIT;
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
		cleanup_user(user);
		free(user);
	}

	gotr_ecdhe_key_clear(&room->data.my_longterm_skey);

	free(room);
}
