#ifndef _MESSAGING_H
#define _MESSAGING_H

#include "util.h"
#include "crypto.h"
#include "gotr.h"

struct gotr_user;
struct gotr_roomdata;

unsigned char *gotr_pack_pair_channel_init(struct gotr_roomdata *room, struct gotr_user *user, size_t *len);
unsigned char *gotr_pack_pair_channel_est (struct gotr_roomdata *room, struct gotr_user *user, size_t *len);
unsigned char *gotr_pack_flake_z          (struct gotr_roomdata *room, struct gotr_user *user, size_t *len);
unsigned char *gotr_pack_flake_R          (struct gotr_roomdata *room, struct gotr_user *user, size_t *len);
unsigned char *gotr_pack_flake_validate   (struct gotr_roomdata *room, struct gotr_user *user, size_t *len);
unsigned char *gotr_pack_msg              (struct gotr_roomdata *room, char *plain_msg, size_t *len);
int gotr_parse_pair_channel_init(struct gotr_roomdata *room, struct gotr_user *user, unsigned char *packed_msg, size_t len);
int gotr_parse_pair_channel_est (struct gotr_roomdata *room, struct gotr_user *user, unsigned char *packed_msg, size_t len);
int gotr_parse_flake_z          (struct gotr_roomdata *room, struct gotr_user *user, unsigned char *packed_msg, size_t len);
int gotr_parse_flake_R          (struct gotr_roomdata *room, struct gotr_user *user, unsigned char *packed_msg, size_t len);
int gotr_parse_flake_validate   (struct gotr_roomdata *room, struct gotr_user *user, unsigned char *packed_msg, size_t len);
char* gotr_parse_msg            (struct gotr_roomdata *room, char *packed_msg, size_t len, struct gotr_user** sender);

#endif
