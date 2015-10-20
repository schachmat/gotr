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

#define GOTR_PROT_VERSION "1"

struct gotr_chatroom;
struct gotr_user;

/**
 * This callback is used by libgotr to broadcast encrypted and base64 encoded
 * messages to all users in a chatroom. The Client should send the message @a
 * b64_msg to every user in @a room_closure either via the chatroom broadcast
 * mechanism of the underlying protocol or if not available as separate messages
 * to each user. The callback should return 1 on success and 0 on failure.
 * This callback must not call any other gotr_ function itself.
 * @param[in] room_closure Closure pointer representing the respective chatroom.
 * This is the Pointer given to gotr_join().
 * @param[in] b64_msg The message to be sent to all users in @a room_closure. The
 * pointer will be invalidated after this call has returned, so make a copy if
 * you need the data later.
 * @return 1 on success, 0 on failure.
 */
typedef int (*gotr_cb_send_all)(void *room_closure, const char *b64_msg);

/**
 * This callback is used by libgotr to send an encrypted and base64 encoded
 * protocol management message to a specific user in a chatroom. The client
 * should send this message @a b64_msg to the user @a user_closure in the
 * chatroom @a room_closure. The callback should return 1 on success and 0 on
 * failure. This callback must not call any other gotr_ function itself.
 * @param[in] room_closure Closure pointer representing the respective chatroom.
 * This is the Pointer given to gotr_join().
 * @param[in] user_closure Closure pointer representing the recipient of the
 * message.
 * This is the Pointer given to gotr_user_joined() or gotr_receive_user().
 * @param[in] b64_msg The message to be sent to all users in @a room_closure. The
 * pointer will be invalidated after this call has returned, so make a copy if
 * you need the data later.
 * @return 1 on success, 0 on failure.
 */
typedef int (*gotr_cb_send_user)(void *room_closure, void *user_closure, const char *b64_msg);

/**
 * Callbacks of this type will be invoked to inform the client about the
 * decrypted content of a received message protected with gotr. The client
 * should display the message in the chatroom @a room_closure coming from user
 * @a user_closure. This callback must not call any other gotr_ function itself.
 * @param[in] room_closure Closure pointer representing the respective chatroom.
 * This is the Pointer given to gotr_join().
 * @param[in] user_closure Closure pointer representing the sender of the message.
 * This is the Pointer given to gotr_user_joined() or gotr_receive_user().
 * @param[in] plain_msg The plain message to display. The
 * pointer will be invalidated after this call has returned, so make a copy if
 * you need the data later.
 */
typedef void (*gotr_cb_receive_user)(void *room_closure, void *user_closure, const char *plain_msg);

/**
 * initialize libgotr.
 * @return 1 on success, 0 on failure.
 */
int gotr_init();

/**
 * Enables the gotr protocol for the given chatroom. You may use different
 * callback functions for different chatrooms/protocols.
 * @param[in] send_all Pointer to the send_all callback function
 * @param[in] send_user Pointer to the send_user callback function
 * @param[in] receive_user Pointer to the receive_user callback function
 * @param[in] room_closure Closure pointer representing the new chatroom. This
 * will not be touched by gotr. It is only passed to the callbacks.
 * @param[in] privkey_filename The absolute filepath where the private key is
 * stored. If the file does not exist, but the containing folder does, a key is
 * generated and saved as the specified name. If you set this argument to NULL,
 * a key is generated and used for this chatroom, but not saved to disk, so it
 * may not be recovered after the chat session.
 * @return A pointer, which should only be remembered and passed to
 * gotr functions when the client needs to refer to this chat room. This is a
 * black-box pointer, do NOT access/change it or the data it points to!
 */
struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_user send_user, gotr_cb_receive_user receive_user, const void *room_closure, const char *privkey_filename);

/**
 * Notify gotr about a new user who just joined a chatroom. This should be
 * called as early as possible to allow fast key establishment with this user.
 * This function must be called even if the same user already has a established
 * gotr connection with the client in another room. The private keys for those
 * two rooms may differ.
 * @param[in] room The pointer returned by gotr_join() to the respective chat room
 * which the user just joined.
 * @param[in] user_closure Closure pointer representing the new user in this
 * Chatroom. This will not be touched by gotr. It is only passed to the
 * callbacks.
 * @return A pointer, which should only be remembered by the client and passed
 * to gotr functions when the client needs to refer to this user. This is a
 * black-box pointer, do NOT access/change it or the data it points to!
 */
struct gotr_user *gotr_user_joined(struct gotr_chatroom *room, const void *user_closure);

/**
 * Notify gotr about a user who just left a chatroom.
 * @param[in] room The pointer returned by gotr_join() to the respective chat room
 * which the user just left.
 * @param[in] user The pointer returned by gotr_user_joined() or gotr_receive_user()
 * to the respective user who left the chatroom @a room.
 */
void gotr_user_left(struct gotr_chatroom *room, struct gotr_user *user);

/**
 * Send a gotr protected message to a chat room.
 * @param[in] room The pointer returned by gotr_join() to which message @a plain_msg
 * should be sent.
 * @param[in] plain_msg The plain text message to send. gotr will automatically
 * encrypt it and send it by calling the gotr_cb_send_all() callback.
 * @return 1 on success, 0 on failure.
 */
int gotr_send(struct gotr_chatroom *room, char *plain_msg);

/**
 * Receive a gotr protected message from a chat room.
 * @param[in] room The pointer returned by gotr_join() from which message @a b64_msg
 * was received.
 * @param[in] b64_msg The base64 encoded, encrypted text message that was received.
 * It should begin with `?GOTR?1`. gotr will automatically
 * decrypt it and call the gotr_cb_receive_user() callback to let the client
 * display it to the user.
 * @return 1 on success, 0 on failure.
 */
int gotr_receive(struct gotr_chatroom *room, char *b64_msg);

/**
 * Establish new ephemeral keypairs with one or all users in a chatroom.
 * @param[in] room The pointer returned by gotr_join() in which the rekey should be
 * executed.
 * @param[in] user The pointer to the user with which a rekey should be executed. If
 * this argument is NULL a rekey is done for each user in the @a room.
 */
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
 * @param[in] b64_msg_in The message, that has been received
 * @return @a user or the newly created gotr_user struct if @a user == NULL
 */
struct gotr_user *gotr_receive_user(struct gotr_chatroom *room, struct gotr_user *user, const void *user_closure, const char *b64_msg_in);

/**
 * Disable gotr for a given chat room. This releases all ressources associated
 * with this room and all users from this room. It also clears the respective
 * keys from memory. Call this as early as possible so no further callbacks
 * refering to this room will occur.
 * @param[in] room The chat room to leave.
 */
void gotr_leave(struct gotr_chatroom *room); //room will be freed

#endif
