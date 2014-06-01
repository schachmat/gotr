#include <crypto_box.h>

struct gotr_chatroom;

typedef int (*gotr_cb_send_all)(const char*);
typedef int (*gotr_cb_send_usr)(const char*, const char*);
typedef void (*gotr_cb_receive_usr)(struct gotr_chatroom*, const char*, const char*);

struct gotr_user {
	char *name;
	char pub_key[crypto_box_PUBLICKEYBYTES];
	struct gotr_user* next;
};

struct gotr_chatroom {
	//sid
	
	unsigned char pub_key[crypto_box_PUBLICKEYBYTES];
	unsigned char sec_key[crypto_box_SECRETKEYBYTES];
	
	struct gotr_user *users;
	gotr_cb_send_all send_all;
	gotr_cb_send_usr send_usr;
	gotr_cb_receive_usr receive_usr;
};

struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr, gotr_cb_receive_usr receive_usr);
void gotr_keyupdate(struct gotr_chatroom *room);
void gotr_send(struct gotr_chatroom *room, char *message);
void gotr_receive(struct gotr_chatroom *room, char *message);
void gotr_add_user(struct gotr_chatroom *room, char *pub_key);
void gotr_leave(struct gotr_chatroom *room); //room will be freed
char* gotr_encode(const unsigned char *in, size_t len);
unsigned char* gotr_decode(const char *in, size_t* len);
