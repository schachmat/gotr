#include <gcrypt.h>
#include <stdio.h>

#include "libgotr.h"

gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr) {
	gotr_chatroom *room;
	
	room = malloc(sizeof(gotr_chatroom));
	room->send_all = send_all;
	room->send_usr = send_usr;
	
	puts("gotr_init() called");
	
	return room;
}

void gotr_leave(gotr_chatroom **room) {
	free(*room);
	room = NULL;
}



int gotr_send(const char* msg) {
	return 0;
}
