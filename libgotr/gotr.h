#ifndef _GOTR_GOTR_H
#define _GOTR_GOTR_H

#define GOTR_GCRYPT_VERSION "1.6.1"
#define GOTR_PROT_VERSION "1"

struct gotr_chatroom;
struct gotr_user;

typedef int (*gotr_cb_send_all)(void *room_closure, const char *b64_msg);
typedef int (*gotr_cb_send_user)(void *room_closure, void *user_closure, const char *b64_msg);
/**
 * @param plain_msg The plain message to display. If the client wants to store
 * it permanently, he has to copy it, the pointer will be considered invalid
 * after this callback returns.
 */
typedef void (*gotr_cb_receive_user)(void *room_closure, void *user_closure, const char *plain_msg);

/// @todo romove
int gotr_init();
struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_user send_user, gotr_cb_receive_user receive_user, const void *room_closure, const char *privkey_filename);
struct gotr_user *gotr_user_joined(struct gotr_chatroom *room, const void *user_closure);
void gotr_user_left(struct gotr_chatroom *room, struct gotr_user *user);
void gotr_keyupdate(struct gotr_chatroom *room);
int gotr_send(struct gotr_chatroom *room, char *plain_msg);
int gotr_receive(struct gotr_chatroom *room, char *b64_msg);

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
 * @param[in] user_closure The users closure, only used if @a user == NULL
 * @param[in] b64_msg The message, that has been received
 * @return @a user or the newly created gotr_user struct if @a user == NULL
 */
struct gotr_user *gotr_receive_user(struct gotr_chatroom *room, struct gotr_user *user, const void *user_closure, const char *b64_msg_in);
void gotr_leave(struct gotr_chatroom *room); //room will be freed

#endif
