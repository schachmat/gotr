#include "crypto.h"

struct gotr_chatroom;
struct gotr_user;

typedef int (*gotr_cb_send_all)(const char*, const struct gotr_chatroom*);
typedef int (*gotr_cb_send_usr)(const char*, const struct gotr_user*);
typedef void (*gotr_cb_receive_usr)(const char*, const struct gotr_user*, const struct gotr_chatroom*);

/**
 * stores key material and other information related to a specific user
 *
 * @var gotr_user::name
 * users name.
 * @var gotr_user::state
 * progress in the key exchange algorithm.
 * @var gotr_user::static_pubkey
 * the long term static key of this user.
 * @var gotr_user::r
 * own (ephemeral) private key to this user.
 * @f$r_{ij0}@f$ and @f$r_{ij1}@f$
 * @var gotr_user::z
 * own corresponding (ephemeral) public keys.
 * @f$z_{ij0} = g^{r_{ij0}} \mod{prime}@f$
 * and @f$z_{ij1} = g^{r_{ij1}} \mod{prime}@f$
 * @var gotr_user::y
 * other users (ephemeral) public keys.
 * @f$y_{ij0} = z_{ji0} = g^{r_{ji0}} \mod{prime}@f$
 * and @f$y_{ij1} = z_{ji1} = g^{r_{ji1}} \mod{prime}@f$
 * @var gotr_user::R
 * own X values for the flake key.
 * @f$R_{ij0} = (\frac{z_{ij1}}{y_{ij0}})^{r_{ij0}} \mod{prime}@f$
 * and @f$R_{ij1} = (\frac{y_{ij1}}{z_{ij0}})^{r_{ij1}} \mod{prime}@f$
 * @var gotr_user::V
 * other users X values for the flake key.
 * @f$V_{ij0} = R_{ji0} = (\frac{z_{ji1}}{y_{ji0}})^{r_{ji0}} \mod{prime}@f$
 * and @f$V_{ij1} = R_{ji1} = (\frac{y_{ji1}}{z_{ji0}})^{r_{ji1}} \mod{prime}@f$
 * @var gotr_user::next
 * link to next user in the list
 */
struct gotr_user {
	char *name;
	char state;
	struct gotr_eddsa_public_key static_pubkey;
	gcry_mpi_t r[2];
	gcry_mpi_t z[2];
	gcry_mpi_t y[2];
	gcry_mpi_t R[2];
	gcry_mpi_t V[2];
	struct gotr_user* next;
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
