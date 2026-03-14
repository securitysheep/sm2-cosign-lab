#ifndef SM2_H
#define SM2_H

#include <openssl/ec.h>
#include <openssl/bn.h>


void print_hex(const char *label, const unsigned char *data, size_t len);
EC_KEY *sm2_init_key();
int sm2_encrypt(const EC_KEY *eckey, const BIGNUM *plaintext_bn, unsigned char *ciphertext, size_t *ciphertext_len);
int sm2_decrypt(const EC_KEY *eckey, const unsigned char *ciphertext, size_t ciphertext_len, BIGNUM *decrypted_bn);

#endif // SM2_H
