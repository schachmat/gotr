#ifndef _GOTR_GOTR_H
#define _GOTR_GOTR_H

#define GOTR_GCRYPT_VERSION "1.6.1"
#define GOTR_PROT_VERSION "1"

struct gotr_chatroom;
struct gotr_user;

typedef int (*gotr_cb_send_all)(void *room_closure, const char *b64_msg);
typedef int (*gotr_cb_send_user)(void *room_closure, void *user_closure, const char *b64_msg);
typedef void (*gotr_cb_receive_user)(void *room_closure, void *user_closure, const char *plain_msg);

int gotr_init(); /// @todo romove
struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_user send_user, gotr_cb_receive_user receive_user, const void *room_closure, const char *privkey_filename);
struct gotr_user *gotr_user_joined(struct gotr_chatroom *room, void *user_closure);
void gotr_keyupdate(struct gotr_chatroom *room);
int gotr_send(struct gotr_chatroom *room, char *plain_msg);
int gotr_receive(struct gotr_chatroom *room, char *b64_msg);
struct gotr_user *gotr_receive_user(struct gotr_chatroom *room, struct gotr_user *user, void *user_closure, char *b64_msg);
void gotr_leave(struct gotr_chatroom *room); //room will be freed

#endif
