#include <stdio.h>
#include "crypto.h"

void print_hex(char *descr, unsigned char *val, unsigned int size) {
	printf("%s: ", descr);
	
	for(unsigned int i = 0; i < size; i++) {
		printf("%02x", val[i]);
	}
	
	printf("\n");
}

int main() {
	struct GOTR_EddsaPrivateKey *private_key;
	struct GOTR_EddsaPublicKey *public_key;
	char data[] = "skjkmsefjhnsefjbnsefjhbnkbyk";
	struct GOTR_EccSignaturePurpose *purpose;
	struct GOTR_EddsaSignature *signature;
	
	private_key = GOTR_eddsa_key_create();
	
	print_hex("private key: ", private_key->d, sizeof(private_key->d));
	
	public_key = malloc(sizeof(struct GOTR_EddsaPublicKey));
	GOTR_eddsa_key_get_public(private_key, public_key);
	
	print_hex("public key: ", public_key->q_y, sizeof(public_key->q_y));
	
	signature = malloc(sizeof(struct GOTR_EddsaSignature));
	purpose = malloc(sizeof(struct GOTR_EccSignaturePurpose) + sizeof(data));
	purpose->size = htonl(sizeof(struct GOTR_EccSignaturePurpose) + sizeof(data));
	purpose->purpose = 1;
	memcpy(purpose + 1, data, sizeof(data));
	GOTR_eddsa_sign(private_key, purpose, signature);
	
	print_hex("signature r: ", signature->r, sizeof(signature->r));
	print_hex("signature s: ", signature->s, sizeof(signature->s));
	
	int succ = GOTR_eddsa_verify(htonl(1), purpose, signature, public_key);
	
	printf("succ: %d\n", succ);
	
	return 0;
}