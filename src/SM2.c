#include "SM2.h"
#include "crypto/gmssl3_adapter.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int resolve_sm2_curve_nid(void) {
    int nid = OBJ_txt2nid("sm2p256v1");
    if (nid == NID_undef) {
        nid = OBJ_txt2nid("SM2");
    }
    if (nid == NID_undef) {
        nid = NID_X9_62_prime256v1;
    }
    return nid;
}

// 打印十六进制数据
void print_hex(const char *label, const unsigned char *data, size_t len) {
    if (!label || !data) {
        fprintf(stderr, "Error: Invalid input to print_hex\n");
        return;
    }
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// 初始化 SM2 密钥对
EC_KEY *sm2_init_key() {
    EC_KEY *eckey = EC_KEY_new_by_curve_name(resolve_sm2_curve_nid());
    if (!eckey) {
        fprintf(stderr, "Error: Failed to create EC_KEY (NID_sm2p256v1)\n");
        return NULL;
    }

    if (EC_KEY_generate_key(eckey) != 1) {
        fprintf(stderr, "Error: Failed to generate SM2 key pair\n");
        EC_KEY_free(eckey);
        return NULL;
    }

    return eckey;
}

// 通用加密/解密辅助函数
static int sm2_process(const EC_KEY *eckey, const unsigned char *input, size_t input_len,
                        unsigned char *output, size_t *output_len, int encrypt) {
    if (!eckey || !input || input_len == 0 || !output || !output_len) {
        fprintf(stderr, "Error: Invalid parameters for %s\n", encrypt ? "encryption" : "decryption");
        return 1;
    }

    int ok = encrypt
        ? gmssl3_sm2_encrypt_with_ec_key(eckey, input, input_len, output, output_len)
        : gmssl3_sm2_decrypt_with_ec_key(eckey, input, input_len, output, output_len);

    if (!ok) {
        fprintf(stderr, "Error: gmssl3 %s failed\n", encrypt ? "encryption" : "decryption");
        return 1;
    }

    return 0;
}

// SM2 加密函数
int sm2_encrypt(const EC_KEY *eckey, const BIGNUM *plaintext_bn, unsigned char *ciphertext, size_t *ciphertext_len) {
    if (!eckey || !plaintext_bn || !ciphertext || !ciphertext_len) {
        fprintf(stderr, "Error: Invalid parameters for sm2_encrypt\n");
        return 1;
    }

    int plaintext_len = BN_num_bytes(plaintext_bn);
    if (plaintext_len <= 0) {
        plaintext_len = 1; // 允许加密数值 0
    }

    unsigned char *plaintext = (unsigned char *)malloc(plaintext_len);
    if (!plaintext) {
        fprintf(stderr, "Error: Memory allocation failed for plaintext buffer\n");
        return 1;
    }

    memset(plaintext, 0, plaintext_len); // 确保缓冲区清零
    if (BN_is_zero(plaintext_bn)) {
        plaintext[0] = 0;
    } else {
        BN_bn2bin(plaintext_bn, plaintext);
    }

    int ret = sm2_process(eckey, plaintext, plaintext_len, ciphertext, ciphertext_len, 1);

    free(plaintext); // 释放分配的内存
    return ret;
}

// SM2 解密函数
int sm2_decrypt(const EC_KEY *eckey, const unsigned char *ciphertext, size_t ciphertext_len, BIGNUM *decrypted_bn) {
    if (!eckey || !ciphertext || ciphertext_len == 0 || !decrypted_bn) {
        fprintf(stderr, "Error: Invalid parameters for sm2_decrypt\n");
        return 1;
    }

    unsigned char decryptedtext[256] = {0}; // 初始化解密缓冲区
    size_t decryptedtext_len = sizeof(decryptedtext);

    int ret = sm2_process(eckey, ciphertext, ciphertext_len, decryptedtext, &decryptedtext_len, 0);
    if (ret != 0) {
        return 1; // 解密失败时直接返回
    }

    if (!BN_bin2bn(decryptedtext, decryptedtext_len, decrypted_bn)) {
        fprintf(stderr, "Error: Failed to convert decrypted text to BIGNUM\n");
        return 1;
    }

    return 0; // 成功
}
