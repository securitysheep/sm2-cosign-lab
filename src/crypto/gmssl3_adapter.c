#include "crypto/gmssl3_adapter.h"

#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <dlfcn.h>
#include <string.h>

typedef int (*gmssl_sm2_encrypt_fn)(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
typedef int (*gmssl_sm2_decrypt_fn)(const SM2_KEY *key, const uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);

static void *g_gmssl_handle = NULL;
static gmssl_sm2_encrypt_fn g_sm2_encrypt_fn = NULL;
static gmssl_sm2_decrypt_fn g_sm2_decrypt_fn = NULL;

static int ensure_gmssl_symbols(void) {
    if (g_sm2_encrypt_fn && g_sm2_decrypt_fn) {
        return 1;
    }

    if (!g_gmssl_handle) {
        g_gmssl_handle = dlopen("/opt/homebrew/opt/gmssl/lib/libgmssl.dylib", RTLD_LAZY | RTLD_LOCAL);
    }
    if (!g_gmssl_handle) {
        g_gmssl_handle = dlopen("libgmssl.dylib", RTLD_LAZY | RTLD_LOCAL);
    }
    if (!g_gmssl_handle) {
        return 0;
    }

    g_sm2_encrypt_fn = (gmssl_sm2_encrypt_fn)dlsym(g_gmssl_handle, "sm2_encrypt");
    g_sm2_decrypt_fn = (gmssl_sm2_decrypt_fn)dlsym(g_gmssl_handle, "sm2_decrypt");

    return g_sm2_encrypt_fn && g_sm2_decrypt_fn;
}

static int bignum_to_fixed_32(const BIGNUM *bn, unsigned char out[32]) {
    if (!bn || !out) {
        return 0;
    }

    int n = BN_num_bytes(bn);
    if (n <= 0 || n > 32) {
        return 0;
    }

    memset(out, 0, 32);
    if (BN_bn2bin(bn, out + (32 - n)) != n) {
        return 0;
    }

    return 1;
}

static int ec_key_to_sm2_key(const EC_KEY *eckey, SM2_KEY *sm2_key) {
    if (!eckey || !sm2_key) {
        return 0;
    }

    const BIGNUM *priv = EC_KEY_get0_private_key(eckey);
    if (!priv) {
        return 0;
    }

    unsigned char d[32] = {0};
    if (!bignum_to_fixed_32(priv, d)) {
        return 0;
    }

    if (sm2_key_set_private_key(sm2_key, d) != 1) {
        return 0;
    }

    return 1;
}

int gmssl3_sm3_digest(const unsigned char *input, size_t input_len, unsigned char output[32]) {
    if (!input || !output || input_len == 0) {
        return 0;
    }

    sm3_digest(input, input_len, output);
    return 1;
}

int gmssl3_sm2_encrypt_with_ec_key(const EC_KEY *eckey, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    SM2_KEY sm2_key;
    if (!ensure_gmssl_symbols()) {
        return 0;
    }

    if (!ec_key_to_sm2_key(eckey, &sm2_key)) {
        return 0;
    }

    if (!input || !output || !output_len || input_len == 0) {
        return 0;
    }

    return g_sm2_encrypt_fn(&sm2_key, input, input_len, output, output_len) == 1;
}

int gmssl3_sm2_decrypt_with_ec_key(const EC_KEY *eckey, const unsigned char *input, size_t input_len, unsigned char *output, size_t *output_len) {
    SM2_KEY sm2_key;
    if (!ensure_gmssl_symbols()) {
        return 0;
    }

    if (!ec_key_to_sm2_key(eckey, &sm2_key)) {
        return 0;
    }

    if (!input || !output || !output_len || input_len == 0) {
        return 0;
    }

    return g_sm2_decrypt_fn(&sm2_key, input, input_len, output, output_len) == 1;
}
