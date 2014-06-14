#include <gcrypt.h>

int gotr_bdgka_init();
int gotr_gen_BD_X_value(gcry_mpi_t* ret, const gcry_mpi_t nom, const gcry_mpi_t denom, const gcry_mpi_t pow);
void gotr_gen_BD_keypair(gcry_mpi_t* privkey, gcry_mpi_t* pubkey);
