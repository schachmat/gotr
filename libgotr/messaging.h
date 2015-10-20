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

#ifndef _MESSAGING_H
#define _MESSAGING_H

/**
 * @file messaging.h
 * @brief todo
 * @todo document non gotr.h usage.
 */

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
