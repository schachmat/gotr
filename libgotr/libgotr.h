struct gotr_chatroom;

typedef int (*gotr_cb_send_all)(const char*);
typedef int (*gotr_cb_send_usr)(const char*, const char*);
typedef void (*gotr_cb_receive_usr)(struct gotr_chatroom*, const char*, const char*);

struct gotr_user {
	char *name;
	char *pub_key;
};

struct gotr_user_list {
   struct gotr_user user;
   struct gotr_user_list* next;
};

struct gotr_chatroom {
	//sid
	struct gotr_user_list *users;
	gotr_cb_send_all send_all;
	gotr_cb_send_usr send_usr;
	gotr_cb_receive_usr receive_usr;
};

struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr, gotr_cb_receive_usr receive_usr, struct gotr_user_list *users);
void gotr_keyupdate(struct gotr_chatroom *room);
void gotr_send(struct gotr_chatroom *room, char *message);
void gotr_receive(struct gotr_chatroom *room, char *message);
void gotr_leave(struct gotr_chatroom *room); //room will be freed
