#include <stdlib.h>
#include <stdio.h>

#include "libgotr.h"

void gotr_setup(struct gotr_chatroom *room)
{
	crypto_box_keypair(room->pub_key, room->sec_key);
}

struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr, gotr_cb_receive_usr receive_usr)
{
	struct gotr_chatroom *room;

	room = malloc(sizeof(struct gotr_chatroom));
	room->users = users;
	room->send_all = send_all;
	room->send_usr = send_usr;
	room->receive_usr = receive_usr;

	gotr_setup(room);

	puts("gotr_init() called");

	return room;
}

void gotr_keyupdate(struct gotr_chatroom *room)
{
	
}

void gotr_send(struct gotr_chatroom *room, char *message)
{
	room->send_all(message);
}

void gotr_receive(struct gotr_chatroom *room, char *message)
{
	if(message[0] == '/') {
		gotr_add_user(room, message + 1)
	} else {
		room->receive_usr(room, "jemand", message); //message for user
	}
}

void gotr_add_user(struct gotr_chatroom *room, char *pub_key)
{
	struct gotr_user **user = &room->users;
	
	while(*user != NULL) {
		user = &user->next;
	}
	
	*user = malloc(sizeof(struct gotr_user));
	
	//memcpy((*user)->pub_key, const void *str2, size_t n)
}

void gotr_leave(struct gotr_chatroom *room)
{
	free(room);
}
