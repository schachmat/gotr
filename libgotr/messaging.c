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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <gcrypt.h>
#include <arpa/inet.h>

#include "user.h"
#include "util.h"
#include "crypto.h"
#include "gka.h"

static inline int check_params_create_msg(const struct gotr_roomdata *room,
										  struct gotr_user *user,
										  void **msg,
										  size_t len,
										  char *msgtype)
{
	if(!room || !(*msg = calloc(len, 1))) {
		gotr_eprintf("packing %s failed:", msgtype);
		return 0;
	}

//	gotr_eprintf("packing %s", msgtype);
	return 1;
}


/**
 * Encrypts the message and calculates the hmac to prepare for sending.
 *
 * @param[in] user The user who will receive this message.
 * @param[in,out] msg A pointer to the message which shall be encrypted with the
 * first sizeof(struct gotr_hash_code) bytes serving as a padding/placeholder,
 * where the HMAC will be stored.
 * @param[in] msglen The length of @a msg in bytes.
 * @param[out] len On success this will be set to @a msglen.
 * @param[in] generation The key generation to use. 0 means pre-key (used for
 * pair channel establish message) and 1 is used for the following handshake
 * messages.
 * @param[in] next_type The next message type which will be sent to this user to
 * finish the handshake.
 * @return @a msg on success, NULL on failure.
 */
static inline unsigned char *encrypt_and_hmac(struct gotr_user *user,
											  unsigned char *msg,
											  size_t msglen,
											  size_t *len,
											  int generation,
											  gotr_msgtype next_type)
{
	void *enc = msg + sizeof(struct gotr_hash_code);
	const size_t enclen = msglen - sizeof(struct gotr_hash_code);

	if (gotr_symmetric_encrypt(enc, enclen, &user->our_sym_key[generation], &user->our_sym_iv[generation], enc) != enclen) {
		gotr_eprintf("could not encrypt msg");
		return NULL;
	}
	gotr_hmac(&user->our_hmac_key[generation], enc, enclen, (struct gotr_hash_code *)msg);

	user->next_sending_msgtype = next_type;
	*len = msglen;
	return msg;
}

/**
 * Encrypts the message and calculates the hmac to prepare for sending.
 *
 * @param[in] room The room context.
 * @param[in] user The user from which this message was received.
 * @param[in,out] packed_msg A pointer to the encrypted message with the
 * first sizeof(struct gotr_hash_code) bytes containing the HMAC.
 * @param[in] len The length of @a packed_msg in bytes.
 * @param[in] len_should Checked for equality with len.
 * @param[in] generation The key generation to use. 0 means pre-key (used for
 * pair channel establish message) and 1 is used for the following handshake
 * messages.
 * @param[in] msgtype The message type, only used for debugging.
 * @return 1 on success, 0 on failure.
 */
static inline int check_hmac_decrypt(struct gotr_roomdata *room,
									 struct gotr_user *user,
									 unsigned char *packed_msg,
									 size_t len,
									 size_t len_should,
									 int generation,
									 const char* msgtype)
{
	struct gotr_hash_code hmac;
	void *enc = packed_msg + sizeof(struct gotr_hash_code);
	const size_t enclen = len - sizeof(hmac);

	if (!room || !packed_msg || len != len_should)
		return 0;

//	gotr_eprintf("parsing %s", msgtype);

	gotr_hmac(&user->our_hmac_key[generation], enc, enclen, &hmac);
	if (0 != memcmp(&hmac, packed_msg, sizeof(hmac))) {
		gotr_eprintf("hmac mismatch");
		return 0;
	}

	if (gotr_symmetric_decrypt(enc, enclen, &user->our_sym_key[generation], &user->our_sym_iv[generation], enc) != enclen) {
		gotr_eprintf("could not decrypt msg");
		return 0;
	}
	return 1;
}

unsigned char *gotr_pack_pair_channel_init(struct gotr_roomdata *room,
										   struct gotr_user *user,
										   size_t *len)
{
	struct msg_pair_channel_init *msg;

	if (!check_params_create_msg(room, user, (void*)&msg, sizeof(*msg), "pair_channel_init"))
		return NULL;

	gotr_ecdhe_key_get_public(&user->my_dhe_skey, &msg->sender_dhe_pkey);

	/// @todo: is this check needed or can we just set circle_valid to 0 anyway?
	if (user->next_sending_msgtype == GOTR_MSG)
		room->circle_valid = 0;
	user->next_sending_msgtype = GOTR_PAIR_CHAN_ESTABLISH;
	*len = sizeof(*msg);
	return (unsigned char *)msg;
}

unsigned char *gotr_pack_pair_channel_est(struct gotr_roomdata *room,
										  struct gotr_user *user,
										  size_t *len)
{
	struct msg_pair_channel_est *msg;

	if (!check_params_create_msg(room, user, (void*)&msg, sizeof(*msg), "pair_channel_est"))
		return NULL;

	memcpy(&msg->enc.sender_longterm_pkey, &room->my_longterm_pkey, sizeof(room->my_longterm_pkey));

	return encrypt_and_hmac(user, (unsigned char *)msg, sizeof(*msg), len, 0, GOTR_FLAKE_z);
}

unsigned char *gotr_pack_flake_z(struct gotr_roomdata *room,
								 struct gotr_user *user,
								 size_t *len)
{
	struct msg_flake_z *msg;
	if (!check_params_create_msg(room, user, (void*)&msg, sizeof(*msg), "flake_z"))
		return NULL;

	serialize_point(&msg->enc.sender_z[0], sizeof(msg->enc.sender_z[0]), user->my_z[0]);
	serialize_point(&msg->enc.sender_z[1], sizeof(msg->enc.sender_z[1]), user->my_z[1]);

	return encrypt_and_hmac(user, (unsigned char *)msg, sizeof(*msg), len, 1, GOTR_FLAKE_R);
}

unsigned char *gotr_pack_flake_R(struct gotr_roomdata *room,
								 struct gotr_user *user,
								 size_t *len)
{
	struct msg_flake_R *msg;
	if (!check_params_create_msg(room, user, (void*)&msg, sizeof(*msg), "flake_R"))
		return NULL;

	serialize_point(&msg->enc.sender_R[0], sizeof(msg->enc.sender_R[0]), user->my_X[0]);
	serialize_point(&msg->enc.sender_R[1], sizeof(msg->enc.sender_R[1]), user->my_X[1]);

	return encrypt_and_hmac(user, (unsigned char *)msg, sizeof(*msg), len, 1, GOTR_FLAKE_VALIDATE);
}

unsigned char *gotr_pack_flake_validate(struct gotr_roomdata *room,
										struct gotr_user *user,
										size_t *len)
{
	struct msg_flake_validate *msg;
	struct gotr_point p[8];
	if (!check_params_create_msg(room, user, (void*)&msg, sizeof(*msg), "flake_validate"))
		return NULL;

	serialize_point(&p[0], sizeof(p[0]), user->my_z[0]);
	serialize_point(&p[1], sizeof(p[1]), user->my_z[1]);
	serialize_point(&p[2], sizeof(p[2]), user->his_z[0]);
	serialize_point(&p[3], sizeof(p[3]), user->his_z[1]);
	serialize_point(&p[4], sizeof(p[4]), user->my_X[0]);
	serialize_point(&p[5], sizeof(p[5]), user->my_X[1]);
	serialize_point(&p[6], sizeof(p[6]), user->his_X[0]);
	serialize_point(&p[7], sizeof(p[7]), user->his_X[1]);
	gotr_hmac(&user->our_flake_auth, p, sizeof(p), &msg->enc.flake_hash);

	return encrypt_and_hmac(user, (unsigned char *)msg, sizeof(*msg), len, 1, GOTR_MSG);
}

/**
 * Derives usable key material from the given point. This point usually is the
 * circle key.
 *
 * @param[in] keypoint The point from which the key material is to be derived
 * @param[out] hmac Where to save the auth key for HMAC usage
 * @param[out] key Where to save the symmetric key
 * @param[out] iv Where to save the symmetric iv
 */
static void derive_key_material(const gcry_mpi_point_t keypoint,
								struct gotr_auth_key* hmac,
								struct gotr_sym_key* key,
								struct gotr_sym_iv* iv)
{
	struct gotr_point keydata;
	struct gotr_hash_code keyhash;

	serialize_point(&keydata, sizeof(keydata), keypoint);
	gotr_hash(&keydata, sizeof(keydata), &keyhash);
	gotr_sym_derive_key(&keyhash, key, iv);
	gotr_hmac_derive_key(hmac, key, &keydata, sizeof(struct gotr_point), NULL);
}

/**
 * Calculates the circle key for every user with a finished flake key exchange
 * state. The generated key will be used to derive a hmac and a symetric
 * encryption key, both of which are saved in the apropriate fields within the
 * supplied gotr_roomdata struct @a room.
 *
 * @param[in] room The room for which to calculate a circle key. We only take
 * users into account with which we exchanged a flake key previously.
 * @param[out] len_ret The size of the returned pointer in bytes.
 * @param[out] n The amount of X values returned.
 * @return An array of the serialized X values used in the flake key generation
 * or NULL on error.
 */
static void* calc_circle_key(struct gotr_roomdata *room, size_t *len_ret, uint32_t *n)
{
	struct gotr_user* first = room->users;
	struct gotr_user* cur;
	struct gotr_user* pre;
	struct gotr_point* ret = NULL;
	struct gotr_point* rt = NULL;
	gcry_mpi_point_t* X;
	gcry_mpi_point_t* Xt;
	gcry_mpi_point_t keypoint = NULL;
	size_t len_X = 4 * sizeof(gcry_mpi_point_t*);
	uint32_t i;

	*n = 0;
	*len_ret = 4 * sizeof(struct gotr_point);
	while (first && first->next_sending_msgtype != GOTR_MSG)
		first = first->next;
	pre = cur = first;

	if (!cur) {
		/* just a warning, nothing serious
		 * TODO: return a 1-user circle key? */
		gotr_eprintf("calc_circle_key: no other users in room");
		return NULL;
	}
	if (!(ret = malloc(*len_ret)) || !(X = malloc(len_X))) {
		gotr_eprintf("calc_circle_key: could not malloc:");
		free(ret);
		return NULL;
	}
	memset(ret, 0, *len_ret);
	memset(X, 0, len_X);

	while ((cur = cur->next)) {
		if (cur->next_sending_msgtype != GOTR_MSG)
			continue;

		*len_ret += 4 * sizeof(struct gotr_point);
		len_X += 4 * sizeof(gcry_mpi_point_t*);
		if (!(rt = realloc(ret, *len_ret)) || !(Xt = realloc(X, len_X))) {
			gotr_eprintf("calc_circle_key: could not realloc:");
			free(ret);
			free(X);
			return NULL;
		}
		ret = rt;
		X = Xt;

		X[*n] = pre->his_X[0];
		X[*n+1] = pre->his_X[1];

		// calculate the W values to connect the circle
		X[*n+2] = X[*n+3] = NULL;
		gotr_ecbd_gen_X_value(&X[*n+2], pre->his_z[1], cur->my_z[1], pre->my_r[0]);
		gotr_ecbd_gen_X_value(&X[*n+3], pre->my_z[0], cur->his_z[0], cur->my_r[1]);

		serialize_point(&ret[*n], sizeof(struct gotr_point), pre->his_X[0]);
		serialize_point(&ret[*n+1], sizeof(struct gotr_point), pre->his_X[1]);
		serialize_point(&ret[*n+2], sizeof(struct gotr_point), X[*n+2]);
		serialize_point(&ret[*n+3], sizeof(struct gotr_point), X[*n+3]);

		*n += 4;
		pre = cur;
	}

	X[*n] = pre->his_X[0];
	X[*n+1] = pre->his_X[1];

	// calculate the W values to connect the circle
	X[*n+2] = X[*n+3] = NULL;
	gotr_ecbd_gen_X_value(&X[*n+2], pre->his_z[1], first->my_z[1], pre->my_r[0]);
	gotr_ecbd_gen_X_value(&X[*n+3], pre->my_z[0], first->his_z[0], first->my_r[1]);

	serialize_point(&ret[*n], sizeof(struct gotr_point), pre->his_X[0]);
	serialize_point(&ret[*n+1], sizeof(struct gotr_point), pre->his_X[1]);
	serialize_point(&ret[*n+2], sizeof(struct gotr_point), X[*n+2]);
	serialize_point(&ret[*n+3], sizeof(struct gotr_point), X[*n+3]);

	gcry_mpi_point_release(X[*n+3]);
	X[*n+3] = NULL;
	*n += 4;
	gotr_ecbd_gen_circle_key(&keypoint, X, first->my_z[1], pre->my_r[0]);

	// don't need the W's anymore, release them from their memorable prison
	for (i = 0; i<*n; i+=4) {
		gcry_mpi_point_release(X[i+2]);
		gcry_mpi_point_release(X[i+3]);
	}
	free(X);

	derive_key_material(keypoint, &room->my_circle_auth, &room->my_circle_key,
						&room->my_circle_iv);
	gcry_mpi_point_release(keypoint);
	room->circle_valid = 1;
	return ret;
}

static struct gotr_user* derive_circle_key(struct gotr_roomdata* room,
										   const struct gotr_point* Xdata,
										   size_t len_Xdata)
{
	struct gotr_user* cur;
	struct gotr_user* ret = NULL;
	gcry_mpi_point_t keypoint = NULL;
	gcry_mpi_point_t* X = malloc(len_Xdata * sizeof(gcry_mpi_point_t*));
	size_t i;
	size_t j;

	if (!X) {
		gotr_eprintf("derive_circle_key: could not malloc:");
		return NULL;
	}

	X[0] = deserialize_point(&Xdata[0], sizeof(struct gotr_point));
	if (!gcry_mpi_ec_curve_point(X[0], edctx)) {
		gotr_eprintf("received data points are not on curve");
		goto quit;
	}

	for (i = 1, j = 1; i < len_Xdata; i++, j++) {
		X[j] = deserialize_point(&Xdata[i], sizeof(struct gotr_point));
		if (!gcry_mpi_ec_curve_point(X[j], edctx)) {
			gotr_eprintf("received data points are not on curve");
			goto quit;
		}
		if (ret)
			continue;

		// see if we know a user matching the last two X values. If one is
		// found, he is the sender of the message (no one else knows our X
		// values). Put the remaining X values in front, so the circle can be
		// connected correctly.
		for (cur = room->users; cur; cur = cur->next) {
			if (!cur->my_X[0] || !cur->my_X[1] ||
				gotr_point_cmp(X[j-1], cur->my_X[0]) ||
				gotr_point_cmp(X[j], cur->my_X[1]))
				continue;
			ret = cur;
			memmove(&X[len_Xdata - j - 1], X,
					(j + 1) * sizeof(gcry_mpi_point_t*));
			j = -1;
			break;
		}
	}

	if (!ret)
		goto quit;

	gcry_mpi_point_release(X[len_Xdata - 1]);
	X[len_Xdata - 1] = NULL;
	gotr_ecbd_gen_circle_key(&keypoint, X, ret->my_z[1], ret->my_r[0]);

	derive_key_material(keypoint, &ret->his_circle_auth, &ret->his_circle_key,
						&ret->his_circle_iv);
	gcry_mpi_point_release(keypoint);

quit:
	for (i = 0; i < len_Xdata; i++)
		gcry_mpi_point_release(X[i]);
	free(X);
	return ret;
}

unsigned char *gotr_pack_msg(struct gotr_roomdata *room,
							 char *plain_msg,
							 size_t *len)
{
	unsigned char* msg;
	unsigned char* text;
	struct msg_text_header* head;
	size_t len_text;
	size_t len_keys = 0;
	uint32_t count_keys = 0;
	void* keys = NULL;

	if (!room || !plain_msg || !len) {
		gotr_eprintf("gotr_pack_msg: invalid parameters given");
		return NULL;
	}

	len_text = strlen(plain_msg);
	*len = sizeof(struct msg_text_header) + len_text;

	if (!room->circle_valid && !(keys = calc_circle_key(room, &len_keys, &count_keys)))
		return NULL;
	msg = malloc(*len += len_keys);
	memcpy(msg + sizeof(struct msg_text_header), keys, len_keys);
	memset(keys, 0, len_keys);
	free(keys);

	head = (struct msg_text_header*)msg;
	head->clen = htonl(count_keys);
	text = msg + sizeof(struct msg_text_header) + len_keys;

	if (gotr_symmetric_encrypt(plain_msg, len_text, &room->my_circle_key,
							   &room->my_circle_iv, text) != len_text) {
		gotr_eprintf("gotr_pack_msg: could not encrypt plain text message.");
		return NULL;
	}
	gotr_hmac(&room->my_circle_auth, msg + sizeof(struct gotr_hash_code),
			  *len - sizeof(struct gotr_hash_code), &head->hmac);

	return msg;
}

int gotr_parse_pair_channel_init(struct gotr_roomdata *room,
								 struct gotr_user *user,
								 unsigned char *packed_msg,
								 size_t len)
{
	struct msg_pair_channel_init *msg = (struct msg_pair_channel_init*)packed_msg;
	struct gotr_hash_code exchanged_key;

//	gotr_eprintf("parsing pair_channel_init");

	if(!room || !packed_msg || len != sizeof(*msg))
		return 0;

	memcpy(&user->his_dhe_pkey, &msg->sender_dhe_pkey, sizeof(user->his_dhe_pkey));

	if (!gotr_ecdhe(&user->my_dhe_skey, &user->his_dhe_pkey, &exchanged_key)) {
		gotr_eprintf("ecdhe failed.");
		return 0;
	}
	gotr_sym_derive_key(&exchanged_key, &user->our_sym_key[0],
						&user->our_sym_iv[0]);
	gotr_hmac_derive_key(&user->our_hmac_key[0], &user->our_sym_key[0],
	                     &exchanged_key, sizeof(exchanged_key), NULL);

	/// @todo: is this check needed or can we just set circle_valid to 0 anyway?
	if (user->next_expected_msgtype == GOTR_MSG)
		room->circle_valid = 0;
	user->next_expected_msgtype = GOTR_PAIR_CHAN_ESTABLISH;
	return 1;
}

int gotr_parse_pair_channel_est(struct gotr_roomdata *room,
								struct gotr_user *user,
								unsigned char *packed_msg,
								size_t len)
{
	struct msg_pair_channel_est *msg = (struct msg_pair_channel_est*)packed_msg;
	struct gotr_hash_code triple_dhe[3];
	struct gotr_hash_code seed;
	unsigned char sw;

	if(!check_hmac_decrypt(room, user, packed_msg, len, sizeof(*msg), 0, "pair_channel_est"))
		return 0;

	memcpy(&user->his_longterm_pkey, &msg->enc.sender_longterm_pkey, sizeof(user->his_longterm_pkey));
	/// @todo: check pubkey trust level

	// Derive shared key for encryption and hmac from triple-DH
	// See https://whispersystems.org/blog/simplifying-otr-deniability/
	sw = memcmp(&room->my_longterm_pkey, &user->his_longterm_pkey, sizeof(struct gotr_dhe_pkey)) > 0;
	if (!gotr_ecdhe(&user->my_dhe_skey, &user->his_longterm_pkey, &triple_dhe[sw]) ||
	    !gotr_ecdhe(&room->my_longterm_skey, &user->his_dhe_pkey, &triple_dhe[!sw]) ||
	    !gotr_ecdhe(&user->my_dhe_skey, &user->his_dhe_pkey, &triple_dhe[2])) {
		gotr_eprintf("triple ecdhe failed.");
		return 0;
	}
	gotr_hash(triple_dhe, sizeof(triple_dhe), &seed);
	gotr_sym_derive_key(&seed, &user->our_sym_key[1], &user->our_sym_iv[1]);
	gotr_hmac_derive_key(&user->our_hmac_key[1], &user->our_sym_key[1], &seed, sizeof(seed), NULL);

	gotr_ecbd_gen_keypair(&user->my_r[0], &user->my_z[0]);
	gotr_ecbd_gen_keypair(&user->my_r[1], &user->my_z[1]);

	user->next_expected_msgtype = GOTR_FLAKE_z;
	return 1;
}

int gotr_parse_flake_z(struct gotr_roomdata *room,
					   struct gotr_user *user,
					   unsigned char *packed_msg,
					   size_t len)
{
	struct msg_flake_z *msg = (struct msg_flake_z*)packed_msg;
	if(!check_hmac_decrypt(room, user, packed_msg, len, sizeof(*msg), 1, "flake_z"))
		return 0;

	user->his_z[0] = deserialize_point(&msg->enc.sender_z[0], sizeof(msg->enc.sender_z[0]));
	user->his_z[1] = deserialize_point(&msg->enc.sender_z[1], sizeof(msg->enc.sender_z[1]));
	if (!gcry_mpi_ec_curve_point(user->his_z[0], edctx) ||
		!gcry_mpi_ec_curve_point(user->his_z[1], edctx)) {
		gotr_eprintf("received data points are not on curve");
		return 0;
	}

	gotr_ecbd_gen_X_value(&user->my_X[0], user->his_z[1], user->my_z[1], user->my_r[0]);
	gotr_ecbd_gen_X_value(&user->my_X[1], user->my_z[0], user->his_z[0], user->my_r[1]);

	user->next_expected_msgtype = GOTR_FLAKE_R;
	return 1;
}

int gotr_parse_flake_R(struct gotr_roomdata *room,
					   struct gotr_user *user,
					   unsigned char *packed_msg,
					   size_t len)
{
	struct msg_flake_R *msg = (struct msg_flake_R*)packed_msg;
	gcry_mpi_point_t keypoint = NULL;
	struct gotr_point keydata;
	if(!check_hmac_decrypt(room, user, packed_msg, len, sizeof(*msg), 1, "flake_R"))
		return 0;

	user->his_X[0] = deserialize_point(&msg->enc.sender_R[0], sizeof(msg->enc.sender_R[0]));
	user->his_X[1] = deserialize_point(&msg->enc.sender_R[1], sizeof(msg->enc.sender_R[1]));
	if (!gcry_mpi_ec_curve_point(user->his_X[0], edctx) ||
		!gcry_mpi_ec_curve_point(user->his_X[1], edctx)) {
		gotr_eprintf("received data points are not on curve");
		return 0;
	}

	gotr_ecbd_gen_flake_key(&keypoint, user->his_z[0], user->my_r[1], user->my_X[1], user->my_X[0], user->his_X[1]);
	serialize_point(&keydata, sizeof(keydata), keypoint);
	gotr_hmac_derive_key(&user->our_flake_auth, &user->our_sym_key[1], &keydata, sizeof(struct gotr_point), NULL);
	gcry_mpi_point_release(keypoint);

	user->next_expected_msgtype = GOTR_FLAKE_VALIDATE;
	return 1;
}

int gotr_parse_flake_validate(struct gotr_roomdata *room,
							  struct gotr_user *user,
							  unsigned char *packed_msg,
							  size_t len)
{
	struct msg_flake_validate *msg = (struct msg_flake_validate*)packed_msg;
	struct gotr_point p[8];
	struct gotr_hash_code hmac;
	if(!check_hmac_decrypt(room, user, packed_msg, len, sizeof(*msg), 1, "flake_validate"))
		return 0;

	serialize_point(&p[0], sizeof(p[0]), user->his_z[0]);
	serialize_point(&p[1], sizeof(p[1]), user->his_z[1]);
	serialize_point(&p[2], sizeof(p[2]), user->my_z[0]);
	serialize_point(&p[3], sizeof(p[3]), user->my_z[1]);
	serialize_point(&p[4], sizeof(p[4]), user->his_X[0]);
	serialize_point(&p[5], sizeof(p[5]), user->his_X[1]);
	serialize_point(&p[6], sizeof(p[6]), user->my_X[0]);
	serialize_point(&p[7], sizeof(p[7]), user->my_X[1]);
	gotr_hmac(&user->our_flake_auth, p, sizeof(p), &hmac);
	if (memcmp(&hmac, &msg->enc.flake_hash, sizeof(hmac))) {
		gotr_eprintf("flake key hmac mismatch");
		return 0;
	}

	user->next_expected_msgtype = GOTR_MSG;
	room->circle_valid = 0;
	return 1;
}

char* gotr_parse_msg(struct gotr_roomdata *room, char *packed_msg, size_t len, struct gotr_user** sender)
{
	struct msg_text_header *msg = (struct msg_text_header*)packed_msg;
	struct gotr_user* cur = NULL;
	struct gotr_user** pre_next = &(room->users);
	struct gotr_hash_code hmac;
	uint32_t clen = ntohl(msg->clen);
	char* Xdata = packed_msg + sizeof(struct msg_text_header);
	const void *hmac_data = packed_msg + sizeof(hmac);
	const size_t hmac_len = len - sizeof(hmac);
	char* enc = Xdata + clen * sizeof(struct gotr_point);
	const size_t enclen = packed_msg + len - enc;
	char* ret;

	if (!room || !packed_msg || len < sizeof(struct msg_text_header) ||
		len < sizeof(struct msg_text_header) + clen * sizeof(struct gotr_point))
		return NULL;
	*sender = NULL;
	ret = malloc(enclen + 1);

//	gotr_eprintf("parsing text message");

	if (0 == clen ||
		!(*sender = derive_circle_key(room, (struct gotr_point*)Xdata, clen))) {
		for (cur = room->users; cur; cur = cur->next) {
			gotr_hmac(&cur->his_circle_auth, hmac_data, hmac_len, &hmac);
			if (!memcmp(&hmac, packed_msg, sizeof(hmac))) {
				*sender = cur;
				// move sender to the beginning of the user list to reduce
				// derivation time for future messages from him
				*pre_next = cur->next;
				cur->next = room->users;
				room->users = cur;
				break;
			}
			pre_next = &(cur->next);
		}
		if (!*sender) {
			gotr_eprintf("could not derive sender");
			free(ret);
			return NULL;
		}
	}

	if (!cur) {
		gotr_hmac(&(*sender)->his_circle_auth, hmac_data, hmac_len, &hmac);
		if (memcmp(&hmac, packed_msg, sizeof(hmac))) {
			gotr_eprintf("hmac mismatch");
			free(ret);
			return NULL;
		}
	}

	if (gotr_symmetric_decrypt(enc, enclen, &(*sender)->his_circle_key,
	                           &(*sender)->his_circle_iv, ret) != enclen) {
		gotr_eprintf("could not decrypt msg");
		free(ret);
		return NULL;
	}
	ret[enclen] = '\0';
	return ret;
}
