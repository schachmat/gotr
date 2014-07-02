#ifndef _GOTR_LIBGOTR_PLUGIN_H
#define _GOTR_LIBGOTR_PLUGIN_H

#define GOTR_PROT_VERSION "1"

struct gotr_chatroom;

typedef int (*gotr_cb_send_all)(void *room_data, const char *b64_msg);
typedef int (*gotr_cb_send_usr)(void *room_data, void *user_data, const char *b64_msg);
typedef void (*gotr_cb_receive_usr)(void *room_data, void *user_data, const char *plain_msg);

int gotr_init();
struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr, gotr_cb_receive_usr receive_usr, void *room_data);
void gotr_user_joined(struct gotr_chatroom *room, void *user_data);
void gotr_keyupdate(struct gotr_chatroom *room);
int gotr_send(struct gotr_chatroom *room, char *plain_msg);
int gotr_receive(struct gotr_chatroom *room, char *b64_msg);
void gotr_leave(struct gotr_chatroom *room); //room will be freed

#endif
