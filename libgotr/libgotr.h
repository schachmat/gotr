#ifndef _GOTR_LIBGOTR_H
#define _GOTR_LIBGOTR_H

struct gotr_chatroom;
struct gotr_user;

typedef int (*gotr_cb_send_all)(const struct gotr_chatroom *room, const char *message);
typedef int (*gotr_cb_send_usr)(const struct gotr_chatroom *room, void *user_data, const char *message);
typedef void (*gotr_cb_receive_usr)(const struct gotr_chatroom *room, void *user_data, const char *message);

int gotr_init();
struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr, gotr_cb_receive_usr receive_usr);
void gotr_user_joined(struct gotr_chatroom *room, void *user_data);
void gotr_keyupdate(struct gotr_chatroom *room);
int gotr_send(struct gotr_chatroom *room, char *message);
int gotr_receive(struct gotr_chatroom *room, char *message);
void gotr_leave(struct gotr_chatroom *room); //room will be freed

#endif
