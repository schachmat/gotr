#include <stdio.h>

#include "test.h"
#include "key.c"
#include "util.c"
#include "b64.c"
#include "gotr.c"
#include "messaging.c"
#include "crypto.c"
#include "gka.c"

int tests_run = 0;

static char *test_init()
{
	mu_assert("ERROR: gotr_init failed", gotr_init() == 1);
	return 0;
}

static char *test_serialization()
{
	struct gotr_ecdhe_private_key priv;
	struct gotr_ecdhe_public_key pub;
	gcry_mpi_t x1, x2, y1, y2;
	gcry_mpi_point_t p1, p2;
	unsigned char *ser;

	gotr_ecdhe_key_create(&priv);
	gotr_ecdhe_key_get_public(&priv, &pub);

	p1 = deserialize_point(pub.q_y, 32);
	ser = serialize_point(p1);
	mu_assert("ERROR: deserialization->serialization failed", memcmp(pub.q_y, ser, 32) == 0);

	x1 = gcry_mpi_new(0);
	x2 = gcry_mpi_new(0);
	y1 = gcry_mpi_new(0);
	y2 = gcry_mpi_new(0);
	p2 = deserialize_point(ser, 32);
	free(ser);
	gcry_mpi_ec_get_affine(x1, y1, p1, edctx);
	gcry_mpi_ec_get_affine(x2, y2, p2, edctx);
	int res = gcry_mpi_cmp(x1, x2) || gcry_mpi_cmp(y1, y2);
	gcry_mpi_point_release(p1);
	gcry_mpi_point_release(p2);

	mu_assert("ERROR: serialization->deserialization failed", res == 0);
	return 0;
}

static char *test_flake()
{
	struct gotr_user u[2];
	gotr_gen_BD_keypair(&u[0].r[0], &u[0].z[0]);
	gotr_gen_BD_keypair(&u[0].r[1], &u[0].z[1]);
	u[1].y[0] = u[0].z[0];
	u[1].y[1] = u[0].z[1];
	gotr_gen_BD_keypair(&u[1].r[0], &u[1].z[0]);
	gotr_gen_BD_keypair(&u[1].r[1], &u[1].z[1]);
	u[0].y[0] = u[1].z[0];
	u[0].y[1] = u[1].z[1];
	mu_assert("ERROR: flake X0 failed", gotr_gen_BD_X_value(&u[0].R[0], u[0].y[1], u[0].z[1], u[0].r[0]));
	mu_assert("ERROR: flake X1 failed", gotr_gen_BD_X_value(&u[0].R[1], u[0].z[0], u[0].y[0], u[0].r[1]));
	mu_assert("ERROR: flake X2 failed", gotr_gen_BD_X_value(&u[1].R[0], u[1].y[1], u[1].z[1], u[1].r[0]));
	mu_assert("ERROR: flake X3 failed", gotr_gen_BD_X_value(&u[1].R[1], u[1].z[0], u[1].y[0], u[1].r[1]));
	u[1].V[0] = u[0].R[0];
	u[1].V[1] = u[0].R[1];
	u[0].V[0] = u[1].R[0];
	u[0].V[1] = u[1].R[1];
	mu_assert("ERROR: flake f0 failed", gotr_gen_BD_flake_key(&u[0].flake_key, u[0].y[0], u[0].r[1], u[0].R[0], u[0].R[1], u[0].V[1]));
	mu_assert("ERROR: flake f1 failed", gotr_gen_BD_flake_key(&u[1].flake_key, u[1].y[0], u[1].r[1], u[1].R[0], u[1].R[1], u[1].V[1]));

/*	u[0].next = u[1].next = NULL;
	if (!gotr_gen_BD_circle_key(u[0].flake_key, &u[0]))
		gotr_eprintf("c0 failed");
	if (gcry_mpi_cmp(u[0].flake_key, u[1].flake_key))
		gotr_eprintf("flake != c0");
	gcry_mpi_dump(u[0].flake_key);
	gotr_eprintf("");
	if (!gotr_gen_BD_circle_key(u[1].flake_key, &u[1]))
		gotr_eprintf("c1 failed");
	if (gcry_mpi_cmp(u[1].flake_key, u[0].flake_key))
		gotr_eprintf("flake != c1");
	gcry_mpi_dump(u[1].flake_key);
	gotr_eprintf("");
	gotr_eprintf("circle keys match");*/

	mu_assert("ERROR: flake keys do not match", 0 == gcry_mpi_cmp(u[0].flake_key, u[1].flake_key));
	return 0;
}

static char *all_tests() {
	mu_run_test(test_init);
	mu_run_test(test_serialization);
	mu_run_test(test_flake);
	return 0;
}

int main(int argc, char **argv) {
	char *result = all_tests();
	result ? printf("%s\n", result) : printf("ALL TESTS PASSED\n");
	printf("Tests run: %d\n", tests_run);
	return result != 0;
}
