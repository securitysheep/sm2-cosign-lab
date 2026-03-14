#ifndef GMSSL3_ADAPTER_H
#define GMSSL3_ADAPTER_H

#include <openssl/ec.h>
#include <stddef.h>

int gmssl3_sm3_digest(const unsigned char *input, size_t input_len, unsigned char output[32]);
int gmssl3_sm2_encrypt_with_ec_key(const EC_KEY *eckey, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len);
int gmssl3_sm2_decrypt_with_ec_key(const EC_KEY *eckey, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len);

#endif
