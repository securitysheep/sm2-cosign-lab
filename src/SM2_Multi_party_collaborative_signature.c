#include "SM2_Multi_party_collaborative_signature.h"
#include "SM2.h"
#include "crypto/gmssl3_adapter.h"
#include <openssl/objects.h>

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

// int main() {
//     // 定义参与方数量
//     int user_count = 5;

//     // 初始化椭圆曲线参数
//     Elliptic_Curve *E = SM2_init_EC_params();
//     if (!E) {
//         fprintf(stderr, "Error: Failed to initialize elliptic curve parameters\n");
//         return 1;
//     }

//     // 初始化服务器和参与方，并生成私钥 d 和公钥 P
//     User *users = (User *)malloc(user_count * sizeof(User));
//     Server server = {0};
//     if (SM2_init_system(users, &server, user_count) != 0) {
//         fprintf(stderr, "Error: Failed to initialize SM2 system\n");
//         SM2_free_params(E);
//         return 1;
//     }

//     // 对 m 个参与方协同生成协同签名的组公钥
//     Point Pm = { .x = BN_new(), .y = BN_new() };
//     if (!Pm.x || !Pm.y) {
//         fprintf(stderr, "Error: Memory allocation failed for group public key\n");
//         SM2_free_params(E);
//         free_user_resources(users);
//         free_server_resources(&server, user_count);
//         return 1;
//     }

//     if (SM2_gen_group_pubkey(E, users, &server, &Pm, user_count) != 0) {
//         fprintf(stderr, "Error: Failed to generate group public key\n");
//         SM2_free_params(E);
//         free_user_resources(users);
//         free_server_resources(&server, user_count);
//         BN_free(Pm.x);
//         BN_free(Pm.y);
//         return 1;
//     }
//     print_Point("组公钥 (Pm)", &Pm);

//     // 初始化消息和签名
//     const unsigned char *message = (const unsigned char *)"message digest";
//     printf("明文消息:\t%s\n", message);

//     unsigned char Z[SM3_DIGEST_LENGTH] = {0};
//     params_hash(E, &users[0], Z);
//     print_BN("拼接后哈希 (Z)", byte2bn(Z, SM3_DIGEST_LENGTH));

//     // 签名
//     SM2_sig sig = { .r = BN_new(), .s = BN_new() };
//     if (!sig.r || !sig.s) {
//         fprintf(stderr, "Error: Memory allocation failed for signature\n");
//         SM2_free_params(E);
//         free_user_resources(users);
//         free_server_resources(&server, user_count);
//         BN_free(Pm.x);
//         BN_free(Pm.y);
//         return 1;
//     }

//     SM2_Signature(E, users, &server, Z, message, &sig, user_count);
//     print_SM2_sig("签名结果", &sig);

//     // 验签
//     if (SM2_Verify(E, &Pm, Z, message, &sig)) {
//         printf("基于SM2的多方协同签名验签通过\n");
//     } else {
//         printf("基于SM2的多方协同签名验签未通过\n");
//     }

//     // 清理资源
//     SM2_free_params(E);
//     free_user_resources(users);
//     free_server_resources(&server, user_count);
//     BN_free(sig.r);
//     BN_free(sig.s);
//     BN_free(Pm.x);
//     BN_free(Pm.y);

//     return 0;
// }

// 生成指定范围 [min, max) 内的随机整数
void RAND_bn(BIGNUM *rand_num, const BIGNUM *min, const BIGNUM *max) {
    if (!rand_num || !min || !max) {
        fprintf(stderr, "Error: Invalid input to RAND_bn\n");
        return;
    }

    BIGNUM *range = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!range || !ctx) {
        perror("Error allocating memory for BIGNUM or BN_CTX");
        BN_free(range);
        BN_CTX_free(ctx);
        return;
    }

    BN_sub(range, max, min); // 计算范围

    int attempt = 0;
    while (attempt++ < 256) {
        unsigned char buf[32];  // 256 位随机数
        if (RAND_bytes(buf, sizeof(buf)) != 1) {
            fprintf(stderr, "Error: RAND_bytes failed\n");
            BN_free(range);
            BN_CTX_free(ctx);
            return;
        }

        BN_bin2bn(buf, sizeof(buf), rand_num);  // 转换为 BIGNUM
        BN_mod(rand_num, rand_num, range, ctx);
        BN_add(rand_num, rand_num, min);  // rand_num = rand_num + min

        // 检查是否在范围内
        if (BN_cmp(rand_num, min) >= 0 && BN_cmp(rand_num, max) < 0)
            break;
    }

    BN_free(range);
    BN_CTX_free(ctx);
}

// 大整数转字节串
unsigned char* bn2byte(const BIGNUM* bn, size_t* byte_length) {
    if (!bn || !byte_length) {
        fprintf(stderr, "Error: Invalid input to bn2byte\n");
        return NULL;
    }

    // 获取大整数的字节长度
    *byte_length = BN_num_bytes(bn);

    // 分配内存
    unsigned char* byte_array = (unsigned char*)malloc(*byte_length);
    if (!byte_array) {
        perror("Failed to allocate memory for byte_array");
        return NULL;
    }

    // 将大整数转换为字节串
    BN_bn2bin(bn, byte_array);
    return byte_array;
}

// 字节串转大整数
BIGNUM* byte2bn(const unsigned char* byte_array, size_t length) {
    if (!byte_array || length == 0) {
        fprintf(stderr, "Error: Invalid input to byte2bn\n");
        return NULL;
    }

    BIGNUM* bn = BN_new();
    if (!bn) {
        perror("Failed to allocate BIGNUM");
        return NULL;
    }

    // 将字节串转换为大整数
    BN_bin2bn(byte_array, length, bn);
    return bn;
}

// 字节串拼接
unsigned char* concat_bytes(const unsigned char **byte_arrays, const size_t *lengths, const size_t numbyte_arrays, size_t *byte_length) {
    if (!byte_arrays || !lengths || numbyte_arrays == 0 || !byte_length) {
        fprintf(stderr, "Error: Invalid input to concat_bytes\n");
        return NULL;
    }

    // 计算总长度
    size_t totalLength = 0;
    for (size_t i = 0; i < numbyte_arrays; i++) {
        totalLength += lengths[i];
    }

    // 分配内存
    unsigned char* result = (unsigned char*)malloc(totalLength);
    if (!result) {
        perror("Failed to allocate memory for concatenated byte array");
        return NULL;
    }

    // 拼接字节串
    size_t offset = 0;
    for (size_t i = 0; i < numbyte_arrays; i++) {
        memcpy(result + offset, byte_arrays[i], lengths[i]);
        offset += lengths[i];
    }

    *byte_length = totalLength; // 输出拼接后的长度
    return result;
}

// SM3 哈希函数
void SM3(const unsigned char* input, size_t input_length, unsigned char* hash_output) {
    if (!input || input_length == 0 || !hash_output) {
        fprintf(stderr, "Error: Invalid input to SM3\n");
        return;
    }

    if (!gmssl3_sm3_digest(input, input_length, hash_output)) {
        fprintf(stderr, "Error: gmssl3 SM3 digest failed\n");
        return;
    }
}

// 检查点是否为无穷远点
int Point_is_infinity(const Point *P) {
    if (!P) {
        fprintf(stderr, "Error: Invalid input to Point_is_infinity\n");
        return 0;  // 假设不是无穷远点，避免崩溃
    }
    return (BN_is_zero(P->x) && BN_is_zero(P->y));
}

// 椭圆曲线加法
void Elliptic_add(const Elliptic_Curve *E, Point *r, const Point *P, const Point *Q) {
    if (!E || !r || !P || !Q) {
        fprintf(stderr, "Error: Invalid input to Elliptic_add\n");
        return;
    }

    // 如果 P 是无穷远点，返回 Q
    if (Point_is_infinity(P)) {
        BN_copy(r->x, Q->x);
        BN_copy(r->y, Q->y);
        return;
    }

    // 如果 Q 是无穷远点，返回 P
    if (Point_is_infinity(Q)) {
        BN_copy(r->x, P->x);
        BN_copy(r->y, P->y);
        return;
    }

    // 如果 P 和 Q 是对称点，返回无穷远点
    BIGNUM *sum_y = BN_new();
    if (!sum_y) {
        perror("Failed to allocate memory for sum_y");
        return;
    }

    BN_add(sum_y, P->y, Q->y);
    if (BN_cmp(P->x, Q->x) == 0 && BN_cmp(E->p, sum_y) == 0) {
        BN_zero(r->x);
        BN_zero(r->y);
        BN_free(sum_y);
        return;
    }

    BIGNUM *lambda = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!lambda || !ctx) {
        perror("Failed to allocate memory for lambda or BN_CTX");
        BN_free(sum_y);
        return;
    }

    // 计算斜率 λ
    if (BN_cmp(P->x, Q->x) != 0) {
        // λ = (Q.y - P.y) / (Q.x - P.x) mod p
        BIGNUM *numerator = BN_new();
        BIGNUM *denominator = BN_new();
        if (!numerator || !denominator) {
            perror("Failed to allocate memory for numerator or denominator");
            BN_free(sum_y);
            BN_free(lambda);
            BN_CTX_free(ctx);
            return;
        }

        BN_sub(numerator, Q->y, P->y);
        BN_sub(denominator, Q->x, P->x);

        // 使用 BN_mod_inverse 计算 (Q.x - P.x)^(-1) mod p
        if (BN_mod_inverse(denominator, denominator, E->p, ctx) == NULL) {
            fprintf(stderr, "Error: Failed to compute modular inverse of denominator\n");
            BN_free(numerator);
            BN_free(denominator);
            BN_free(sum_y);
            BN_free(lambda);
            BN_CTX_free(ctx);
            return;
        }

        BN_mod_mul(lambda, numerator, denominator, E->p, ctx);

        BN_free(numerator);
        BN_free(denominator);
    } else {
        // λ = (3 * P.x^2 + a) / (2 * P.y) mod p
        BIGNUM *numerator = BN_new();
        BIGNUM *denominator = BN_new();
        BIGNUM *temp = BN_new();
        if (!numerator || !denominator || !temp) {
            perror("Failed to allocate memory for numerator, denominator or temp");
            BN_free(sum_y);
            BN_free(lambda);
            BN_CTX_free(ctx);
            return;
        }

        BN_mod_mul(temp, P->x, P->x, E->p, ctx); // P.x^2
        BN_mul_word(temp, 3); // 3 * P.x^2
        BN_add(numerator, temp, E->a); // 3 * P.x^2 + a

        BN_copy(temp, P->y);
        BN_mul_word(temp, 2); // 2 * P.y
        if (BN_mod_inverse(denominator, temp, E->p, ctx) == NULL) {
            fprintf(stderr, "Error: Failed to compute modular inverse of denominator\n");
            BN_free(numerator);
            BN_free(denominator);
            BN_free(temp);
            BN_free(sum_y);
            BN_free(lambda);
            BN_CTX_free(ctx);
            return;
        }

        BN_mod_mul(lambda, numerator, denominator, E->p, ctx);

        BN_free(numerator);
        BN_free(denominator);
        BN_free(temp);
    }

    // 计算结果点
    BIGNUM *temp_x = BN_new();
    BIGNUM *temp_y = BN_new();
    if (!temp_x || !temp_y) {
        perror("Failed to allocate memory for temp_x or temp_y");
        BN_free(sum_y);
        BN_free(lambda);
        BN_CTX_free(ctx);
        return;
    }

    // x_r = λ^2 - P.x - Q.x
    BN_mod_mul(temp_x, lambda, lambda, E->p, ctx); // λ^2
    BN_sub(temp_x, temp_x, P->x); // λ^2 - P.x
    BN_sub(temp_x, temp_x, Q->x); // λ^2 - P.x - Q.x
    BN_mod(temp_x, temp_x, E->p, ctx);
    BN_add(temp_x, temp_x, E->p);
    BN_mod(temp_x, temp_x, E->p, ctx);

    // y_r = λ * (P.x - x_r) - P.y
    BN_sub(temp_y, P->x, temp_x); // P.x - x_r
    BN_mod_mul(temp_y, lambda, temp_y, E->p, ctx); // λ * (P.x - x_r)
    BN_sub(temp_y, temp_y, P->y); // λ * (P.x - x_r) - P.y
    BN_mod(temp_y, temp_y, E->p, ctx);
    BN_add(temp_y, temp_y, E->p);
    BN_mod(temp_y, temp_y, E->p, ctx);

    BN_copy(r->x, temp_x);
    BN_copy(r->y, temp_y);

    // 清理
    BN_free(sum_y);
    BN_free(lambda);
    BN_free(temp_x);
    BN_free(temp_y);
    BN_CTX_free(ctx);
}

// 椭圆曲线倍点
void Elliptic_mul(const Elliptic_Curve *E, Point *r, const BIGNUM *d, const Point *P) {
    if (!E || !r || !d || !P) {
        fprintf(stderr, "Error: Invalid input to Elliptic_mul\n");
        return;
    }

    // r = (0, 0) (无穷远点)
    BN_zero(r->x);
    BN_zero(r->y);

    // Q = P
    Point Q = { .x = BN_new(), .y = BN_new() };
    if (!Q.x || !Q.y) {
        perror("Failed to allocate memory for point Q");
        return;
    }

    BN_copy(Q.x, P->x);
    BN_copy(Q.y, P->y);

    BIGNUM *n = BN_new();
    if (!n) {
        perror("Failed to allocate memory for n");
        BN_free(Q.x);
        BN_free(Q.y);
        return;
    }

    BN_copy(n, d);

    // 倍点
    while (!BN_is_zero(n)) {
        if (BN_is_odd(n)) {
            Elliptic_add(E, r, r, &Q);
        }
        Elliptic_add(E, &Q, &Q, &Q); // Q = Q + Q (倍点)
        BN_rshift1(n, n); // n >>= 1
    }

    BN_free(n);
    BN_free(Q.x);
    BN_free(Q.y);
}

// 初始化椭圆曲线参数
Elliptic_Curve* SM2_init_EC_params() {
    // 为椭圆曲线参数分配内存
    Elliptic_Curve *E = malloc(sizeof(Elliptic_Curve));
    if (!E) {
        perror("Failed to allocate memory for Elliptic_Curve");
        return NULL;
    }

    // 初始化椭圆曲线参数中的大数
    E->p = BN_new();
    E->a = BN_new();
    E->b = BN_new();
    E->G.x = BN_new();
    E->G.y = BN_new();
    E->n = BN_new();
    E->h = BN_new();

    // 检查大数分配是否成功
    if (!E->p || !E->a || !E->b || !E->G.x || !E->G.y || !E->n || !E->h) {
        fprintf(stderr, "Failed to allocate BIGNUMs for Elliptic_Curve parameters\n");
        SM2_free_params(E);
        return NULL;
    }

    // 创建 SM2 椭圆曲线的 EC_KEY 实例
    EC_KEY *eckey = EC_KEY_new_by_curve_name(resolve_sm2_curve_nid());
    if (!eckey) {
        fprintf(stderr, "Failed to create EC_KEY for SM2 curve\n");
        SM2_free_params(E);
        return NULL;
    }

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if (!group) {
        fprintf(stderr, "Failed to get EC_GROUP from EC_KEY\n");
        EC_KEY_free(eckey);
        SM2_free_params(E);
        return NULL;
    }

    const EC_POINT *generator = EC_GROUP_get0_generator(group);
    if (!generator) {
        fprintf(stderr, "Failed to get generator from EC_GROUP\n");
        EC_KEY_free(eckey);
        SM2_free_params(E);
        return NULL;
    }

    // 获取曲线参数并检查返回值
    if (!EC_GROUP_get_curve_GFp(group, E->p, E->a, E->b, NULL)) {
        fprintf(stderr, "Failed to get curve parameters\n");
        EC_KEY_free(eckey);
        SM2_free_params(E);
        return NULL;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(group, generator, E->G.x, E->G.y, NULL)) {
        fprintf(stderr, "Failed to get generator coordinates\n");
        EC_KEY_free(eckey);
        SM2_free_params(E);
        return NULL;
    }

    if (!EC_GROUP_get_order(group, E->n, NULL)) {
        fprintf(stderr, "Failed to get curve order\n");
        EC_KEY_free(eckey);
        SM2_free_params(E);
        return NULL;
    }

    if (!EC_GROUP_get_cofactor(group, E->h, NULL)) {
        fprintf(stderr, "Failed to get curve cofactor\n");
        EC_KEY_free(eckey);
        SM2_free_params(E);
        return NULL;
    }

    EC_KEY_free(eckey);

    return E;
}

// 初始化单个参与方
int initialize_user(User *user, int id) {
    if (!user) {
        return 1;
    }

    memset(user, 0, sizeof(*user));

    // 分配存储 ID 的内存
    char *id_str = (char *)malloc(4 * sizeof(char));
    if (id_str == NULL) {
        fprintf(stderr, "Memory allocation failed for user ID\n");
        return 1;
    }
    snprintf(id_str, 4, "%03d", id);
    user->ID = (const unsigned char *)id_str;

    // 设置 ENTL
    size_t idLength = strlen((const char *)user->ID) * 8;
    user->ENTL[0] = (idLength >> 8) & 0xFF;
    user->ENTL[1] = idLength & 0xFF;

    // 初始化 BIGNUMs
    user->d = BN_new();
    user->P.x = BN_new();
    user->P.y = BN_new();
    user->P_group.x = BN_new();
    user->P_group.y = BN_new();
    user->KG.x = BN_new();
    user->KG.y = BN_new();

    if (!user->d || !user->P.x || !user->P.y || !user->P_group.x || !user->P_group.y || !user->KG.x || !user->KG.y) {
        fprintf(stderr, "Failed to allocate BIGNUM for user %d\n", id);
        free_user_resources(user);
        return 1;
    }

    // 创建 EC_KEY 实例
    user->eckey = EC_KEY_new_by_curve_name(resolve_sm2_curve_nid());
    if (user->eckey == NULL) {
        fprintf(stderr, "Failed to initialize EC_KEY for user %d\n", id);
        free_user_resources(user);
        return 1;
    }

    // 生成密钥对
    if (EC_KEY_generate_key(user->eckey) == 0) {
        fprintf(stderr, "Failed to generate keypair for user %d\n", id);
        free_user_resources(user);
        return 1;
    }

    const BIGNUM *private_key = EC_KEY_get0_private_key(user->eckey);
    if (!private_key) {
        fprintf(stderr, "Private key is NULL for user %d\n", id);
        free_user_resources(user);
        return 1;
    }
    BN_copy(user->d, private_key);

    const EC_GROUP *group = EC_KEY_get0_group(user->eckey);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(user->eckey);
    if (!group || !pub_key) {
        fprintf(stderr, "Group or public key is NULL for user %d\n", id);
        free_user_resources(user);
        return 1;
    }

    if (EC_POINT_get_affine_coordinates_GFp(group, pub_key, user->P.x, user->P.y, NULL) == 0) {
        fprintf(stderr, "Failed to get public key coordinates for user %d\n", id);
        free_user_resources(user);
        return 1;
    }

    // 打印用户的私钥和公钥
    // printf("参与方%d:\n", id);
    // print_BN(" 私钥 (d)", user->d);
    // print_Point(" 公钥 (P)", &user->P);

    return 0;
}

// 初始化系统
int SM2_init_system(User *users, Server *server, int user_count) {
    // 初始化服务器
    server->d = BN_new();
    server->P.x = BN_new();
    server->P.y = BN_new();

    if (!server->d || !server->P.x || !server->P.y) {
        fprintf(stderr, "Failed to allocate BIGNUM for server\n");
        free_server_resources(server, user_count);
        return 1;
    }

    server->eckey = EC_KEY_new_by_curve_name(resolve_sm2_curve_nid());
    if (server->eckey == NULL) {
        fprintf(stderr, "Failed to initialize EC_KEY for server\n");
        free_server_resources(server, user_count);
        return 1;
    }

    // 生成服务器的密钥对
    if (EC_KEY_generate_key(server->eckey) == 0) {
        fprintf(stderr, "Failed to generate keypair for server\n");
        free_server_resources(server, user_count);
        return 1;
    }

    const BIGNUM *private_key = EC_KEY_get0_private_key(server->eckey);
    if (!private_key) {
        fprintf(stderr, "Private key is NULL for server\n");
        free_server_resources(server, user_count);
        return 1;
    }
    BN_copy(server->d, private_key);

    const EC_GROUP *group = EC_KEY_get0_group(server->eckey);
    const EC_POINT *pub_key = EC_KEY_get0_public_key(server->eckey);
    if (!group || !pub_key) {
        fprintf(stderr, "Group or public key is NULL for server\n");
        free_server_resources(server, user_count);
        return 1;
    }

    if (EC_POINT_get_affine_coordinates_GFp(group, pub_key, server->P.x, server->P.y, NULL) == 0) {
        fprintf(stderr, "Failed to get public key coordinates for server\n");
        free_server_resources(server, user_count);
        return 1;
    }

    // 动态分配内存
    server->PK = (Point *)malloc(user_count * sizeof(Point));
    server->P_group = (Point *)malloc(user_count * sizeof(Point));
    server->K = (BIGNUM **)malloc(user_count * sizeof(BIGNUM *));

    if (!server->PK || !server->P_group || !server->K) {
        fprintf(stderr, "Failed to allocate memory for server arrays\n");
        free_server_resources(server, user_count);
        return 1;
    }

    // 初始化动态数组
    for (int i = 0; i < user_count; ++i) {
        server->PK[i].x = BN_new();
        server->PK[i].y = BN_new();
        server->P_group[i].x = BN_new();
        server->P_group[i].y = BN_new();
        server->K[i] = BN_new();

        if (!server->PK[i].x || !server->PK[i].y || !server->P_group[i].x || !server->P_group[i].y || !server->K[i]) {
            fprintf(stderr, "Failed to allocate memory for server array elements\n");
            free_server_resources(server, user_count);
            return 1;
        }
    }

    // 初始化每个参与方
    for (int i = 0; i < user_count; ++i) {
        // 初始化用户
        if (initialize_user(&users[i], i) != 0) {
            // 清理已初始化的用户和服务器资源
            for (int j = 0; j < i; ++j) {
                free_user_resources(&users[j]);
            }
            free_server_resources(server, user_count);
            return 1;
        }

        // 将用户公钥复制到服务器
        BN_copy(server->PK[i].x, users[i].P.x);
        BN_copy(server->PK[i].y, users[i].P.y);

        if (!server->PK[i].x || !server->PK[i].y) {
            fprintf(stderr, "Failed to copy public key for user %d to server\n", i);
            // 清理所有资源
            for (int j = 0; j <= i; ++j) {
                free_user_resources(&users[j]);
            }
            free_server_resources(server, user_count);
            return 1;
        }
    }

    return 0;
}

// 对m个参与方协同生成协同签名的组公钥
int SM2_gen_group_pubkey(const Elliptic_Curve *E, User *users, Server *server, Point *Pm, int user_count) {
    if (!E || !users || !server || !Pm || user_count <= 0) {
        return 1;
    }

    BIGNUM *d_prime = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    if (!d_prime || !ctx) {
        fprintf(stderr, "Failed to allocate resources for SM2_gen_group_pubkey\n");
        BN_free(d_prime);
        BN_CTX_free(ctx);
        return 1;
    }

    // 初始化第一个用户的组公钥
    if (!BN_mod_inverse(d_prime, users[0].d, E->n, ctx)) {
        fprintf(stderr, "Failed to compute modular inverse for user[0]\n");
        BN_free(d_prime);
        BN_CTX_free(ctx);
        return 1;
    }

    Elliptic_mul(E, &users[0].P_group, d_prime, &E->G);
    BN_copy(server->P_group[0].x, users[0].P_group.x);
    BN_copy(server->P_group[0].y, users[0].P_group.y);

    if (!server->P_group[0].x || !server->P_group[0].y) {
        fprintf(stderr, "Failed to duplicate group public key for user[0]\n");
        BN_free(d_prime);
        BN_CTX_free(ctx);
        return 1;
    }

    // 依次计算其他用户的组公钥
    for (int i = 1; i < user_count; ++i) {
        if (!BN_mod_inverse(d_prime, users[i].d, E->n, ctx)) {
            fprintf(stderr, "Failed to compute modular inverse for user[%d]\n", i);
            for (int j = 0; j < i; ++j) {
                BN_free(server->P_group[j].x);
                BN_free(server->P_group[j].y);
            }
            BN_free(d_prime);
            BN_CTX_free(ctx);
            return 1;
        }

        Elliptic_mul(E, &users[i].P_group, d_prime, &users[i - 1].P_group);
        BN_copy(server->P_group[i].x, users[i].P_group.x);
        BN_copy(server->P_group[i].y, users[i].P_group.y);

        if (!server->P_group[i].x || !server->P_group[i].y) {
            fprintf(stderr, "Failed to duplicate group public key for user[%d]\n", i);
            for (int j = 0; j <= i; ++j) {
                BN_free(server->P_group[j].x);
                BN_free(server->P_group[j].y);
            }
            BN_free(d_prime);
            BN_CTX_free(ctx);
            return 1;
        }
    }

    // 设置最终组公钥 Pm
    BN_copy(Pm->x, server->P_group[user_count - 1].x);
    BN_copy(Pm->y, server->P_group[user_count - 1].y);

    // 清理资源
    BN_free(d_prime);
    BN_CTX_free(ctx);

    return 0;
}

// 参数哈希为 Z
void params_hash(const Elliptic_Curve *E, const User *user, unsigned char *Z) {
    const unsigned char *byte_arrays[9];
    size_t lengths[9] = {0};

    // 准备参数
    lengths[0] = 2;  // ENTL 长度固定为 2 字节
    lengths[1] = strlen((const char *)user->ID);
    byte_arrays[0] = user->ENTL;
    byte_arrays[1] = user->ID;

    for (int i = 2; i <= 7; ++i) {
        byte_arrays[i] = bn2byte((i == 2) ? E->a : 
                                 (i == 3) ? E->b : 
                                 (i == 4) ? E->G.x : 
                                 (i == 5) ? E->G.y : 
                                 (i == 6) ? user->P.x : user->P.y, &lengths[i]);
        if (!byte_arrays[i]) {
            fprintf(stderr, "Failed to convert BIGNUM to bytes for parameter %d\n", i);
            for (int j = 2; j < i; ++j) {
                free((void *)byte_arrays[j]);
            }
            return;
        }
    }

    // 拼接字节串
    byte_arrays[8] = concat_bytes(byte_arrays, lengths, 8, &lengths[8]);
    if (!byte_arrays[8]) {
        fprintf(stderr, "Failed to concatenate parameters for hash\n");
        for (int i = 2; i < 8; ++i) {
            free((void *)byte_arrays[i]);
        }
        return;
    }

    // 计算哈希值
    SM3(byte_arrays[8], lengths[8], Z);

    // 释放动态分配的内存
    for (int i = 2; i <= 8; ++i) {
        free((void *)byte_arrays[i]);
    }
}

// 消息哈希为 e
BIGNUM *message_hash(const unsigned char *Z, const unsigned char *m) {
    const unsigned char *byte_arrays[2] = {Z, m};
    size_t lengths[2] = {SM3_DIGEST_LENGTH, strlen((const char *)m)};
    size_t totalLength;

    const unsigned char *concatenated = concat_bytes(byte_arrays, lengths, 2, &totalLength);
    if (!concatenated) {
        fprintf(stderr, "Failed to concatenate Z and message\n");
        return NULL;
    }

    unsigned char eBytes[SM3_DIGEST_LENGTH];
    SM3(concatenated, totalLength, eBytes);

    BIGNUM *e = byte2bn(eBytes, SM3_DIGEST_LENGTH);
    if (!e) {
        fprintf(stderr, "Failed to convert bytes to BIGNUM\n");
        free((void *)concatenated);
        return NULL;
    }

    free((void *)concatenated);

    return e;
}

// SM2 签名
void SM2_Signature(const Elliptic_Curve *E, User *users, Server *server, const unsigned char *Z, const unsigned char *m, SM2_sig *sig, int user_count) {
    BN_CTX *ctx = BN_CTX_new();     // 创建用于大数计算的上下文
    if (!ctx) {
        fprintf(stderr, "Failed to create BN_CTX\n");
        return;
    }

    BIGNUM *one = BN_new();         // 存储常数1
    BIGNUM *b = BN_new();           // 用于随机数生成
    BIGNUM *k = BN_new();           // 随机数k
    BIGNUM *d_prime = BN_new();     // 参与方私钥的模逆
    BIGNUM *K = BN_new();           // 中间计算结果K
    BIGNUM *sum = BN_new();         // 存储sig->r和k的和
    BIGNUM *D = BN_new();           // 中间计算结果D
    BIGNUM *Q = BN_new();           // 存储最终计算结果Q
    BIGNUM *b_prime = BN_new();     // b的模逆
    Point R = { .x = BN_new(), .y = BN_new() };

    if (!one || !b || !k || !d_prime || !K || !sum || !D || !Q || !b_prime || !R.x || !R.y) {
        fprintf(stderr, "Failed to allocate BIGNUM\n");
        // 释放已分配的内存
        if (one) BN_free(one);
        if (b) BN_free(b);
        if (k) BN_free(k);
        if (d_prime) BN_free(d_prime);
        if (K) BN_free(K);
        if (sum) BN_free(sum);
        if (D) BN_free(D);
        if (Q) BN_free(Q);
        if (b_prime) BN_free(b_prime);
        if (R.x) BN_free(R.x);
        if (R.y) BN_free(R.y);
        if (ctx) BN_CTX_free(ctx);
        return;
    }

    BIGNUM *e = message_hash(Z, m); // 消息哈希值

    // 设置常数1
    BN_set_word(one, 1);

    int attempt = 0;
    const int max_attempts = 256;
    while (attempt++ < max_attempts) {
        // 将R的坐标清零
        BN_zero(R.x);
        BN_zero(R.y);
        BN_zero(sig->s);
        // 生成随机数b
        RAND_bn(b, one, E->n);

        for (int i = 0; i < user_count; ++i) {
            // 生成随机数k
            RAND_bn(k, one, E->n);
            // 计算参与方私钥的模逆
            BN_mod_inverse(d_prime, users[i].d, E->n, ctx);
            // 计算K = k * d' (模n)
            BN_mod_mul(K, k, d_prime, E->n, ctx);
            // 复制K到服务器的K数组
            BN_copy(server->K[i], K);
            // 计算参与方的KG
            Elliptic_mul(E, &users[i].KG, server->K[i], &E->G);
            // 将KG加到R上
            Elliptic_add(E, &R, &R, &users[i].KG);
        }

        // 计算sig->r = (e + R.x) (模n)
        BN_mod_add(sig->r, e, R.x, E->n, ctx);
        // 计算sig->r + k
        BN_add(sum, sig->r, k);
        // 检查sig->r是否为零或sig->r + k是否等于n
        if (BN_is_zero(sig->r) || BN_cmp(sum, E->n) == 0) {
            continue; // 重新开始循环
        }

        // 计算D = b * user[0].d (模n)
        BN_mod_mul(D, b, users[0].d, E->n, ctx);
        unsigned char ciphertext[2048]; // GMSSL3 下密文长度显著大于明文
        size_t ciphertext_len = 0;

        // 参与方1加密D并解密
        ciphertext_len = sizeof(ciphertext);
        if (sm2_encrypt(users[1].eckey, D, ciphertext, &ciphertext_len) != 0 ||
            sm2_decrypt(users[1].eckey, ciphertext, ciphertext_len, D) != 0) {
            continue;
        }

        int chain_ok = 1;
        // 对后续参与方进行加密和解密
        for (int i = 1; i < user_count - 1; ++i) {
            BN_mod_mul(D, D, users[i].d, E->n, ctx);
            ciphertext_len = sizeof(ciphertext);
            if (sm2_encrypt(users[i + 1].eckey, D, ciphertext, &ciphertext_len) != 0 ||
                sm2_decrypt(users[i + 1].eckey, ciphertext, ciphertext_len, D) != 0) {
                chain_ok = 0;
                break;
            }
        }

        if (!chain_ok) {
            continue;
        }

        // 最后一个参与方的加密和解密
        BN_mod_mul(D, D, users[user_count - 1].d, E->n, ctx);
        ciphertext_len = sizeof(ciphertext);
        if (sm2_encrypt(server->eckey, D, ciphertext, &ciphertext_len) != 0 ||
            sm2_decrypt(server->eckey, ciphertext, ciphertext_len, D) != 0) {
            continue;
        }

        // 计算Q = (K[0] + K[1] + ... + K[user_count-1] + sig->r) * D (模n)
        BN_zero(Q);
        for (int i = 0; i < user_count; ++i) {
            BN_mod_add(Q, Q, server->K[i], E->n, ctx);
        }
        BN_mod_add(Q, Q, sig->r, E->n, ctx);
        BN_mod_mul(Q, Q, D, E->n, ctx);

        // 参与方0的加密和解密
        ciphertext_len = sizeof(ciphertext);
        if (sm2_encrypt(users[0].eckey, Q, ciphertext, &ciphertext_len) != 0 ||
            sm2_decrypt(users[0].eckey, ciphertext, ciphertext_len, Q) != 0) {
            continue;
        }

        // 计算sig->s = (Q * b') - sig->r (模n)
        BN_mod_inverse(b_prime, b, E->n, ctx);
        BN_mod_mul(sig->s, Q, b_prime, E->n, ctx);
        BN_mod_sub(sig->s, sig->s, sig->r, E->n, ctx);

        // 检查sig->s是否为零
        if (BN_is_zero(sig->s)) {
            continue; // 重新开始循环
        }

        break; // 签名成功，退出循环
    }

    if (attempt > max_attempts) {
        BN_zero(sig->r);
        BN_zero(sig->s);
    }

    // 释放所有分配的内存
    BN_free(e);
    BN_free(one);
    BN_free(b);
    BN_free(k);
    BN_free(d_prime);
    BN_free(K);
    BN_free(sum);
    BN_free(D);
    BN_free(Q);
    BN_free(b_prime);
    BN_free(R.x);
    BN_free(R.y);
    BN_CTX_free(ctx);
}

// SM2 验签
int SM2_Verify(const Elliptic_Curve *E, const Point *P, const unsigned char *Z, const unsigned char *m, const SM2_sig *sig) {
    // 签名值 r 和 s 的合法性检查
    if (BN_cmp(sig->r, BN_value_one()) < 0 || BN_cmp(sig->r, E->n) >= 0 ||
        BN_cmp(sig->s, BN_value_one()) < 0 || BN_cmp(sig->s, E->n) >= 0) {
        return 0; // 验签失败
    }

    // 创建用于大数计算的上下文
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        return 0; // 内存分配失败
    }

    // 声明大数
    BIGNUM *t = BN_new();
    if (!t) {
        BN_CTX_free(ctx);
        return 0; // 内存分配失败
    }

    // 计算 t = (r + s) % n
    BN_mod_add(t, sig->r, sig->s, E->n, ctx);
    if (BN_is_zero(t)) {
        BN_free(t);
        BN_CTX_free(ctx);
        return 0; // 验签失败
    }

    BIGNUM *e = message_hash(Z, m);
    if (!e) {
        BN_free(t);
        BN_CTX_free(ctx);
        return 0; // 哈希计算失败
    }

    // 使用椭圆曲线加法和倍点计算 X = (-r * G) + (t * P)
    Point X = { .x = BN_new(), .y = BN_new() };
    if (!X.x || !X.y) {
        BN_free(t);
        BN_free(e);
        BN_CTX_free(ctx);
        return 0; // 内存分配失败
    }

    Point R1 = { .x = BN_new(), .y = BN_new() };
    Point R2 = { .x = BN_new(), .y = BN_new() };
    if (!R1.x || !R1.y || !R2.x || !R2.y) {
        BN_free(t);
        BN_free(e);
        BN_free(X.x);
        BN_free(X.y);
        BN_CTX_free(ctx);
        return 0; // 内存分配失败
    }

    // 计算 -r * G
    BIGNUM *r_prime = BN_new();
    if (!r_prime) {
        BN_free(t);
        BN_free(e);
        BN_free(X.x);
        BN_free(X.y);
        BN_free(R1.x);
        BN_free(R1.y);
        BN_free(R2.x);
        BN_free(R2.y);
        BN_CTX_free(ctx);
        return 0; // 内存分配失败
    }
    BN_sub(r_prime, E->n, sig->r); // 计算 -r

    Elliptic_mul(E, &R1, r_prime, &E->G);  // 计算 -r * G
    Elliptic_mul(E, &R2, t, P);            // 计算 t * P
    Elliptic_add(E, &X, &R1, &R2);         // X = R1 + R2

    // 计算 r' = (e + X.x) % n
    BIGNUM *R = BN_new();
    if (!R) {
        BN_free(t);
        BN_free(e);
        BN_free(X.x);
        BN_free(X.y);
        BN_free(R1.x);
        BN_free(R1.y);
        BN_free(R2.x);
        BN_free(R2.y);
        BN_free(r_prime);
        BN_CTX_free(ctx);
        return 0; // 内存分配失败
    }
    BN_mod_add(R, e, X.x, E->n, ctx);

    // 验证 r' 和 r 是否相等
    int result = (BN_cmp(R, sig->r) == 0); // 验签成功

    // 释放资源
    BN_free(t);
    BN_free(e);
    BN_free(X.x);
    BN_free(X.y);
    BN_free(R1.x);
    BN_free(R1.y);
    BN_free(R2.x);
    BN_free(R2.y);
    BN_free(r_prime);
    BN_free(R);
    BN_CTX_free(ctx);

    return result;
}

// 释放 Elliptic_Curve 结构的资源
void SM2_free_params(Elliptic_Curve *E) {
    if (!E) return; // 检查指针是否为 NULL

    // 释放各个成员的资源
    if (E->p) BN_free(E->p);
    if (E->a) BN_free(E->a);
    if (E->b) BN_free(E->b);
    if (E->G.x) BN_free(E->G.x);
    if (E->G.y) BN_free(E->G.y);
    if (E->n) BN_free(E->n);
    if (E->h) BN_free(E->h);

    free(E); // 释放结构体本身
}

// 释放参与方资源
void free_user_resources(User *user) {
    if (!user) return; // 检查指针是否为 NULL

    if (user->ID) free((void *)user->ID); // 释放 ID
    if (user->d) BN_free(user->d); // 释放私钥
    if (user->P.x) BN_free(user->P.x); // 释放点 P 的 x 坐标
    if (user->P.y) BN_free(user->P.y); // 释放点 P 的 y 坐标
    if (user->P_group.x) BN_free(user->P_group.x);
    if (user->P_group.y) BN_free(user->P_group.y);
    if (user->KG.x) BN_free(user->KG.x);
    if (user->KG.y) BN_free(user->KG.y);
    if (user->eckey) EC_KEY_free(user->eckey); // 释放 EC 密钥

    memset(user, 0, sizeof(*user));
}

// 释放服务器资源
void free_server_resources(Server *server, int user_count) {
    if (!server) return; // 检查指针是否为 NULL

    // 释放服务器私钥
    if (server->d) BN_free(server->d);

    // 释放点 P 的坐标
    if (server->P.x) BN_free(server->P.x);
    if (server->P.y) BN_free(server->P.y);

    // 释放 EC 密钥
    if (server->eckey) EC_KEY_free(server->eckey);

    // 释放 PK 数组
    if (server->PK) {
        for (int i = 0; i < user_count; ++i) {
            if (server->PK[i].x) BN_free(server->PK[i].x);
            if (server->PK[i].y) BN_free(server->PK[i].y);
        }
        free(server->PK); // 释放数组本身
    }

    // 释放 P_group 数组
    if (server->P_group) {
        for (int i = 0; i < user_count; ++i) {
            if (server->P_group[i].x) BN_free(server->P_group[i].x);
            if (server->P_group[i].y) BN_free(server->P_group[i].y);
        }
        free(server->P_group); // 释放数组本身
    }

    // 释放 K 数组
    if (server->K) {
        for (int i = 0; i < user_count; ++i) {
            if (server->K[i]) BN_free(server->K[i]);
        }
        free(server->K); // 释放数组本身
    }
}

// 打印大数
void print_BN(const char* label, const BIGNUM* num) {
    if (!num) return; // 检查指针是否为 NULL
    printf("%s:\n -  ", label);
    BN_print_fp(stdout, num);
    printf("\n");
}

// 打印点
void print_Point(const char* label, const Point* P) {
    if (!P) return; // 检查指针是否为 NULL
    printf("%s:\n", label);
    printf(" X: ");
    BN_print_fp(stdout, P->x);
    printf("\n");
    printf(" Y: ");
    BN_print_fp(stdout, P->y);
    printf("\n");
}

// 打印 SM2 签名
void print_SM2_sig(const char* label, const SM2_sig* sig) {
    if (!sig) return; // 检查指针是否为 NULL
    printf("%s:\n", label);
    printf(" r: ");
    BN_print_fp(stdout, sig->r);
    printf("\n");
    printf(" s: ");
    BN_print_fp(stdout, sig->s);
    printf("\n");
}
