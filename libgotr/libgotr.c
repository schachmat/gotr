#include <gcrypt.h>
#include <stdio.h>

#include "libgotr.h"

static gotr_cb_send_all send_all;
static gotr_cb_send_usr send_usr;

void gotr_init(gotr_cb_send_all all, gotr_cb_send_usr usr) {
	send_all = all;
	send_usr = usr;
	puts("gotr_init() called");
}

int gotr_send(const char* msg) {
	return 0;
}
