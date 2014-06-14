#include <gcrypt.h>

int gotr_bdgka_init();
void gotr_gen_BD_keypair(gcry_mpi_t* privkey, gcry_mpi_t* pubkey);
