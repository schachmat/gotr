#ifndef _MESSAGING_H
#define _MESSAGING_H

#include "util.h"
#include "crypto.h"
#include "gotr.h"

struct gotr_user;
struct gotr_roomdata;

struct est_pair_channel {
	uint32_t                     op;
	struct gotr_EddsaSignature   sig;
	struct gotr_EcdhePublicKey   dh_pub;
	struct gotr_eddsa_public_key sender_pub;
};

struct flake_send_z {
	uint32_t                     op;
	struct gotr_EddsaSignature   sig;
	unsigned char                encrypted[];
};

struct four_mpis {
	unsigned char a1[512];
	unsigned char a2[512];
	unsigned char a3[512];
	unsigned char a4[512];
};

unsigned char *gotr_pack_est_pair_channel(const struct gotr_roomdata *room, struct gotr_user *user);
unsigned char *gotr_pack_flake_z         (const struct gotr_roomdata *room, struct gotr_user *user);
unsigned char *gotr_pack_flake_R         (const struct gotr_roomdata *room, struct gotr_user *user);
unsigned char *gotr_pack_flake_validation(const struct gotr_roomdata *room, struct gotr_user *user);
unsigned char *gotr_pack_msg             (const struct gotr_roomdata *room, char *msg);
int gotr_parse_est_pair_channel(struct gotr_roomdata *room, char *packed_msg);
int gotr_parse_flake_y         (struct gotr_roomdata *room, char *packed_msg);
int gotr_parse_flake_V         (struct gotr_roomdata *room, char *packed_msg);
int gotr_parse_flake_validation(struct gotr_roomdata *room, char *packed_msg);
int gotr_parse_msg             (struct gotr_roomdata *room, char *packed_msg);

#endif
