#ifndef _GOTR_LIBGOTR_H
#define _GOTR_LIBGOTR_H

#define GOTR_GCRYPT_VERSION "1.6.1"

struct gotr_chatroom;
struct gotr_user;

enum {
	GOTR_OP_EST_PAIR_CHANNEL = 0,
	GOTR_OP_FLAKE_SEND_z = 1,
	GOTR_OP_FLAKE_SEND_R = 2,
	GOTR_OP_FLAKE_VALIDATE = 3,
	GOTR_OP_MSG = 4,
	GOTR_OP_MAX = 5
};

unsigned char *gotr_pack_est_pair_channel(const struct gotr_chatroom *room, struct gotr_user *user);
unsigned char *gotr_pack_flake_z         (const struct gotr_chatroom *room, struct gotr_user *user);
unsigned char *gotr_pack_flake_R         (const struct gotr_chatroom *room, struct gotr_user *user);
unsigned char *gotr_pack_flake_validation(const struct gotr_chatroom *room, struct gotr_user *user);
unsigned char *gotr_pack_msg             (const struct gotr_chatroom *room, char *msg);
int gotr_parse_est_pair_channel(struct gotr_chatroom *room, char *packed_msg);
int gotr_parse_flake_y         (struct gotr_chatroom *room, char *packed_msg);
int gotr_parse_flake_V         (struct gotr_chatroom *room, char *packed_msg);
int gotr_parse_flake_validation(struct gotr_chatroom *room, char *packed_msg);
int gotr_parse_msg             (struct gotr_chatroom *room, char *packed_msg);

#endif
