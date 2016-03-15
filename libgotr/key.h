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

#ifndef _GOTR_KEY_H
#define _GOTR_KEY_H

/**
 * load the private key from file or generate a temporary one. If one is
 * generated, it will not use the strong random number generator and therefore
 * should not be used long term. Use the gotr_genkey binary to generate long
 * term keys.
 *
 * @param abs_filename The absolut path to the file. If it does not exist yet
 * or @a abs_filename is NULL, a key is generated to be used in this session.
 * @param key Where to store the loaded/generated key.
 */
void load_privkey(const char* abs_filename, struct gotr_dhe_skey *key);

#endif
