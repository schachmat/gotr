#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "libgotr.h"

void gotr_setup(struct gotr_chatroom *room)
{
	char setup_message[crypto_box_PUBLICKEYBYTES + 3];
	
	crypto_box_keypair(room->pub_key, room->sec_key);
	setup_message[0] = '/';
	setup_message[crypto_box_PUBLICKEYBYTES + 1] = '\0';
	setup_message[crypto_box_PUBLICKEYBYTES + 2] = '\n';
	memcpy(room->pub_key, setup_message + 1, crypto_box_PUBLICKEYBYTES);
	
	room->send_all(setup_message);
}

struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr, gotr_cb_receive_usr receive_usr)
{
	struct gotr_chatroom *room;

	room = malloc(sizeof(struct gotr_chatroom));
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
	if (message[0] == '/') {
		gotr_add_user(room, message + 1);
	} else {
		room->receive_usr(room, "jemand", message); //message for user
	}
}

void gotr_add_user(struct gotr_chatroom *room, char *pub_key)
{
	struct gotr_user *new_user;
	
	new_user = malloc(sizeof(struct gotr_user));
	new_user->next = room->users;
	room->users = new_user;
	
	memcpy(new_user->pub_key, pub_key, crypto_box_PUBLICKEYBYTES);
	
	room->receive_usr(room, "-- user added", pub_key); //debug
}

void gotr_leave(struct gotr_chatroom *room)
{
	struct gotr_user *user;
	
	while (room->users != NULL) {
		user = room->users;
		room->users = user->next;
		free(user);
	}
	
	free(room);
}
