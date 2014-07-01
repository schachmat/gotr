int gotr_init();

struct gotr_chatroom *gotr_join(
	gotr_cb_send_all send_all,
	gotr_cb_send_usr send_usr,
	gotr_cb_receive_usr receive_usr);

void gotr_user_joined(struct gotr_chatroom *room,
	char *name);

void gotr_keyupdate(struct gotr_chatroom *room);

void gotr_leave(struct gotr_chatroom *room);