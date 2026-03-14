#include <stdio.h>
#include <openssl/sm2.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

// 打印椭圆曲线参数和公私钥
void print_sm2_key_info(EC_KEY *eckey) {
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(eckey);
    const BIGNUM *priv_key = EC_KEY_get0_private_key(eckey);

    if (!group || !pub_key || !priv_key) {
        fprintf(stderr, "Failed to retrieve key components.\n");
        return;
    }

    // 打印椭圆曲线名称
    int curve_nid = EC_GROUP_get_curve_name(group);
    const char *curve_name = OBJ_nid2sn(curve_nid);
    printf("Elliptic Curve: %s\n", curve_name);

    // 打印椭圆曲线参数
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    if (EC_GROUP_get_curve_GFp(group, p, a, b, NULL)) {
        printf("Curve Parameters:\n");
        printf("  p: "); BN_print_fp(stdout, p); printf("\n");
        printf("  a: "); BN_print_fp(stdout, a); printf("\n");
        printf("  b: "); BN_print_fp(stdout, b); printf("\n");
    }
    BN_free(p);
    BN_free(a);
    BN_free(b);

    // 打印生成元 G
    const EC_POINT *generator = EC_GROUP_get0_generator(group);
    if (generator) {
        printf("Generator (G):\n");
        BIGNUM *gx = BN_new();
        BIGNUM *gy = BN_new();
        if (EC_POINT_get_affine_coordinates_GFp(group, generator, gx, gy, NULL)) {  
            printf("  Gx: ");
            BN_print_fp(stdout, gx); printf("\n");
            printf("  Gy: ");
            BN_print_fp(stdout, gy); printf("\n");
        }
        BN_free(gx);
        BN_free(gy);
    }

    // 打印椭圆曲线阶 n
    BIGNUM *order = BN_new();
    if (EC_GROUP_get_order(group, order, NULL)) {
        printf("Order (n): ");
        BN_print_fp(stdout, order);
        printf("\n");
    }
    BN_free(order);

    // 打印阶乘因子 h
    BIGNUM *cofactor = BN_new();
    if (EC_GROUP_get_cofactor(group, cofactor, NULL)) {
        printf("Cofactor (h): ");
        BN_print_fp(stdout, cofactor);
        printf("\n");
    }
    BN_free(cofactor);

    // 打印公钥
    printf("Public Key:\n");
    BIGNUM *pub_x = BN_new();
    BIGNUM *pub_y = BN_new();
    if (EC_POINT_get_affine_coordinates_GFp(group, pub_key, pub_x, pub_y, NULL)) {
        printf("  X: ");
        BN_print_fp(stdout, pub_x); printf("\n");
        printf("  Y: ");
        BN_print_fp(stdout, pub_y); printf("\n");
    }
    BN_free(pub_x);
    BN_free(pub_y);

    // 打印私钥
    printf("Private Key:\n");
    BN_print_fp(stdout, priv_key);
    printf("\n");
}

int main() {
    // 创建 EC_KEY 对象并生成密钥对
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    if (!eckey) {
        fprintf(stderr, "Failed to create EC_KEY.\n");
        return -1;
    }

    if (EC_KEY_generate_key(eckey) != 1) {
        fprintf(stderr, "Failed to generate EC_KEY.\n");
        EC_KEY_free(eckey);
        return -1;
    }

    // 打印密钥信息
    print_sm2_key_info(eckey);

    // 释放资源
    EC_KEY_free(eckey);
    return 0;
}
