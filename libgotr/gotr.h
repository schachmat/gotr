/* This file is part of libgotr.
 * (C) 2015 Markus Teich, Jannik Theiß
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

/**
 * @file gotr.h
 * @brief This gotr.h Header defines the external interface of libgotr.
 * Declarations from other libgotr files should not be referenced by
 * applications using libgotr, except when implementing a custom protocol which
 * does not use base64 to embed gotr messages inside existing text-based
 * protocols. See the documentation of file messaging.h for details.
 */

/**
 * @mainpage The libgotr library documentation
 * @section term Terminologies
 *
 * Throughout this documentation the term "client" refers to the application
 * linking against libgotr and using it's code.
 */

#ifndef _GOTR_GOTR_H
#define _GOTR_GOTR_H

#define GOTR_GCRYPT_VERSION "1.6.1"
#define GOTR_PROT_VERSION "1"

struct gotr_chatroom;
struct gotr_user;

/**
 * This callback is used by libgotr to broadcast encrypted and base64 encoded
 * messages to all users in a chatroom. The Client should send the message @a
 * b64_msg to every user in @a room_closure either via the chatroom broadcast
 * mechanism of the underlying protocol or if not available as separate messages
 * to each user.
 * @param room_closure Closure pointer representing the respective chatroom.
 * This is the Pointer given to gotr_join().
 * @param b64_msg The message to be sent to all users in @a room_closure.
 * @return 1 on success, 0 on failure.
 */
typedef int (*gotr_cb_send_all)(void *room_closure, const char *b64_msg);
typedef int (*gotr_cb_send_user)(void *room_closure, void *user_closure, const char *b64_msg);
/**
 * Callbacks of this type will be invoked to inform the client about the
 * decrypted content of a received message protected with gotr. The client
 * should display the message in the chatroom @a room_closure coming from user
 * @a user_closure.
 * @param room_closure Closure pointer representing the respective chatroom.
 * This is the Pointer given to gotr_join().
 * @param user_closure Closure pointer representing the sender of the message.
 * This is the Pointer given to gotr_user_joined() or gotr_receive_user().
 * @param plain_msg The plain message to display. If the client wants to store
 * it permanently, he has to copy it, the pointer will be considered invalid
 * after this callback returns.
 */
typedef void (*gotr_cb_receive_user)(void *room_closure, void *user_closure, const char *plain_msg);

/**
 * initialize libgotr.
 * @todo initialize libgotr in library loader and remove this function
 */
int gotr_init();
struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_user send_user, gotr_cb_receive_user receive_user, const void *room_closure, const char *privkey_filename);
struct gotr_user *gotr_user_joined(struct gotr_chatroom *room, const void *user_closure);
void gotr_user_left(struct gotr_chatroom *room, struct gotr_user *user);
int gotr_send(struct gotr_chatroom *room, char *plain_msg);
int gotr_receive(struct gotr_chatroom *room, char *b64_msg);
void gotr_rekey(struct gotr_chatroom *room, struct gotr_user *user);

/**
 * handle a received b64 encoded gotr message.
 * This function should be called if the client receives a message, regardless
 * of its content. If the client does not have a gotr_user pointer for the
 * author, the client should pass NULL for @a user, so a new gotr_user with the given @a
 * user_closure is created and returned. If the client passes an existing @a
 * user, then @a user_closure is ignored and the same @a user is returned on
 * success.
 *
 * @param[in] room The chatroom, from where the message has been received
 * @param[in] user The gotr_user struct associated with the author of the message or
 * NULL if such does not exist yet
 * @param[in] user_closure The users closure pointer, only used if @a user == NULL
 * @param[in] b64_msg The message, that has been received
 * @return @a user or the newly created gotr_user struct if @a user == NULL
 */
struct gotr_user *gotr_receive_user(struct gotr_chatroom *room, struct gotr_user *user, const void *user_closure, const char *b64_msg_in);
void gotr_leave(struct gotr_chatroom *room); //room will be freed

#endif
