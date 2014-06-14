#include "crypto.h"

struct gotr_chatroom;
struct gotr_user;

typedef int (*gotr_cb_send_all)(const char*, const struct gotr_chatroom*);
typedef int (*gotr_cb_send_usr)(const char*, const struct gotr_user*);
typedef void (*gotr_cb_receive_usr)(const char*, const struct gotr_user*, const struct gotr_chatroom*);

struct gotr_user {
	char *name;                                 ///< users name
	struct gotr_eddsa_public_key static_pubkey; ///< the long term static key of this user
	char state;                                 ///< progress in the key exchange algorithm
	struct gotr_user* next;                     ///< link to next user in the list
};

struct gotr_chatroom {
	//sid

	struct gotr_user *users;         ///< a list of all users in the room
	gotr_cb_send_all send_all;       ///< callback to send a message to every participant in this room
	gotr_cb_send_usr send_usr;       ///< callback to send a message to a specific user
	gotr_cb_receive_usr receive_usr; ///< callback to notify the client about a decrypted message he has to print
};

int gotr_init();
struct gotr_chatroom *gotr_join(gotr_cb_send_all send_all, gotr_cb_send_usr send_usr, gotr_cb_receive_usr receive_usr);
void gotr_keyupdate(struct gotr_chatroom *room);
int gotr_send(struct gotr_chatroom *room, char *message);
int gotr_receive(struct gotr_chatroom *room, char *message);
void gotr_leave(struct gotr_chatroom *room); //room will be freed
