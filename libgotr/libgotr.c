#include <gcrypt.h>
#include <stdio.h>

#include "libgotr.h"

struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr, gotr_cb_receive_usr receive_usr, struct gotr_user_list *users) {
	struct gotr_chatroom *room;

	room = malloc(sizeof(struct gotr_chatroom));
	room->users = users;
	room->send_all = send_all;
	room->send_usr = send_usr;
	room->receive_usr = receive_usr;

	//init crypto stuff

	puts("gotr_init() called");

	return room;
}

void gotr_keyupdate(struct gotr_chatroom *room) {
	
}

void gotr_send(struct gotr_chatroom *room, char *message) {
	room->send_all(message);
}

void gotr_receive(struct gotr_chatroom *room, char *message) {
	//if message for user
	room->receive_usr(room, "jemand", message);
}

void gotr_leave(struct gotr_chatroom *room) {
	free(room);
}
