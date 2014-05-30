#include <gcrypt.h>
#include <stdio.h>

#include "libgotr.h"

struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr) {
	struct gotr_chatroom *room;

	room = malloc(sizeof(struct gotr_chatroom));
	room->send_all = send_all;
	room->send_usr = send_usr;

	puts("gotr_init() called");

	return room;
}
typedef struct sockaddr_un sockaddr_un;
typedef struct timeval timeval;
typedef struct dirent dirent;


void gotr_leave(struct gotr_chatroom **room) {
	free(*room);
	room = NULL;
}



int gotr_send(const char* msg) {
	return 0;
}
