#include <stdio.h>
#include "crypto.h"

void print_hex(char *descr, unsigned char *val, unsigned int size) {
	printf("%s:\t", descr);
	
	for(unsigned int i = 0; i < size; i++) {
		printf("%02x", val[i]);
	}
	
	printf("\n");
}

void test_eddsa() {
	struct gotr_EddsaPrivateKey *private_key;
	struct gotr_EddsaPublicKey *public_key;
	char data[] = "skjkmsefjhnsefjbnsefjhbnkbyk";
	struct gotr_EccSignaturePurpose *purpose;
	struct gotr_EddsaSignature *signature;
	
	printf(" --- EdDSA test --- \n");
	
	private_key = gotr_eddsa_key_create();
	print_hex("private key", private_key->d, sizeof(private_key->d));
	
	public_key = malloc(sizeof(struct gotr_EddsaPublicKey));
	gotr_eddsa_key_get_public(private_key, public_key);
	print_hex("public key", public_key->q_y, sizeof(public_key->q_y));
	
	signature = malloc(sizeof(struct gotr_EddsaSignature));
	purpose = malloc(sizeof(struct gotr_EccSignaturePurpose) + sizeof(data));
	purpose->size = htonl(sizeof(struct gotr_EccSignaturePurpose) + sizeof(data));
	purpose->purpose = 1;
	memcpy(purpose + 1, data, sizeof(data));
	gotr_eddsa_sign(private_key, purpose, signature);
	print_hex("signature r", signature->r, sizeof(signature->r));
	print_hex("signature s", signature->s, sizeof(signature->s));
	
	int succ = gotr_eddsa_verify(htonl(1), purpose, signature, public_key);
	printf("succ: %d\n", succ);
	
	printf("\n\n");
}

void test_ecdhe() {
	struct gotr_EcdhePrivateKey *private_key1;
	struct gotr_EcdhePublicKey *public_key1;
	struct gotr_HashCode *shared_secret1;
	
	struct gotr_EcdhePrivateKey *private_key2;
	struct gotr_EcdhePublicKey *public_key2;
	struct gotr_HashCode *shared_secret2;
	
	printf(" --- ECDHE test --- \n");
	
	private_key1 = gotr_ecdhe_key_create();
	print_hex("private key1", private_key1->d, sizeof(private_key1->d));
	
	public_key1 = malloc(sizeof(struct gotr_EcdhePublicKey));
	gotr_ecdhe_key_get_public(private_key1, public_key1);
	print_hex("public key1", public_key1->q_y, sizeof(public_key1->q_y));
	
	printf("\n");
	
	private_key2 = gotr_ecdhe_key_create();
	print_hex("private key2", private_key2->d, sizeof(private_key2->d));
	
	public_key2 = malloc(sizeof(struct gotr_EcdhePublicKey));
	gotr_ecdhe_key_get_public(private_key2, public_key2);
	print_hex("public key2", public_key2->q_y, sizeof(public_key2->q_y));
	
	printf("\n");
	
	shared_secret1 = malloc(sizeof(struct gotr_HashCode));
	gotr_ecc_ecdh(private_key1, public_key2, shared_secret1);
	print_hex("shared secret1", (unsigned char *)shared_secret1->bits, sizeof(shared_secret1->bits));
	
	shared_secret2 = malloc(sizeof(struct gotr_HashCode));
	gotr_ecc_ecdh(private_key2, public_key1, shared_secret2);
	print_hex("shared secret2", (unsigned char *)shared_secret2->bits, sizeof(shared_secret2->bits));
	
	printf("\n\n");
}

void test_symmetric() {
	struct gotr_SymmetricSessionKey *key;
	struct gotr_SymmetricInitializationVector *iv;
	char salt[] = "ejhbjhbsefjhb";
	char data[] = "omg lol kthxbye";
	unsigned char *data_encrypted;
	char *data_decrypted;
	
	printf(" --- Symmetric test --- \n");
	
	key = malloc(sizeof(struct gotr_SymmetricSessionKey));
	gotr_symmetric_create_session_key(key);
	
	print_hex("aes key", key->aes_key, sizeof(key->aes_key));
	print_hex("twofish key", key->twofish_key, sizeof(key->twofish_key));
	
	iv = malloc(sizeof(struct gotr_SymmetricInitializationVector));
	gotr_symmetric_derive_iv(iv, key, salt, sizeof(salt), NULL);
	
	print_hex("aes iv   ", iv->aes_iv, sizeof(iv->aes_iv));
	print_hex("twofish iv", iv->twofish_iv, sizeof(iv->twofish_iv));
	
	printf("data: %s\n", data);
	
	data_encrypted = malloc(sizeof(data));
	gotr_symmetric_encrypt(data, sizeof(data), key, iv, data_encrypted);
	print_hex("data encrypted", data_encrypted, sizeof(data));
	
	data_decrypted = malloc(sizeof(data));
	gotr_symmetric_decrypt(data_encrypted, sizeof(data), key, iv, data_decrypted);
	printf("data: %s\n", data_decrypted);
	
	printf("\n\n");
}

int main() {
	test_eddsa();
	
	test_ecdhe();
	
	test_symmetric();
	
	return 0;
}