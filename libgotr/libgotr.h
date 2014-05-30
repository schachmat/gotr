typedef int (*gotr_cb_send_all)(const char*);
typedef int (*gotr_cb_send_usr)(const char*, const char*);

struct gotr_chatroom {
	gotr_cb_send_all send_all;
	gotr_cb_send_usr send_usr;
};


void gotr_init(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr);
void gotr_leave(struct gotr_chatroom **room);
