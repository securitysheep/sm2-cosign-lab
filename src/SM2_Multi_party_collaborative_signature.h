#ifndef SM2_Multi_party_collaborative_signature
#define SM2_Multi_party_collaborative_signature

#include <openssl/sm3.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 椭圆曲线点
typedef struct {
    BIGNUM *x;
    BIGNUM *y;
} Point;

// 椭圆曲线
typedef struct {
    BIGNUM *p;
    BIGNUM *a;
    BIGNUM *b;
    BIGNUM *n;
    Point G;
    BIGNUM *h;
} Elliptic_Curve;

// 参与方
typedef struct {
    unsigned char ENTL[2];
    const unsigned char *ID;
    EC_KEY *eckey;
    BIGNUM *d;
    Point P;
    Point P_group;
    Point KG;
} User;

// 服务器
typedef struct {
    EC_KEY *eckey;
    BIGNUM *d;
    Point P;
    Point *PK;       // 动态数组
    Point *P_group;  // 动态数组
    BIGNUM **K;      // 动态数组
} Server;

// SM2签名消息
typedef struct {
    BIGNUM *r;
    BIGNUM *s;
} SM2_sig;


void RAND_bn(BIGNUM *rand_num, const BIGNUM *min, const BIGNUM *max);
unsigned char* bn2byte(const BIGNUM* bn, size_t* byte_length);
BIGNUM* byte2bn(const unsigned char* byte_array, size_t length);
unsigned char* concat_bytes(const unsigned char** byte_arrays, const size_t* lengths, const size_t arrays_num, size_t* byte_length);
void SM3(const unsigned char* input, const size_t input_length, unsigned char* hash_output);
int Point_is_infinity(const Point *P);
void Elliptic_add(const Elliptic_Curve *E, Point *r, const Point *P, const Point *Q);
void Elliptic_mul(const Elliptic_Curve *E, Point *r, const BIGNUM *d, const Point *P);
Elliptic_Curve* SM2_init_EC_params();
int initialize_user(User *user, int id);
int SM2_init_system(User *users, Server *server, int user_count);
int SM2_gen_group_pubkey(const Elliptic_Curve *E, User *users, Server *server, Point *Pm, int user_count);
void params_hash(const Elliptic_Curve *E, const User *user, unsigned char *Z);
BIGNUM* message_hash(const unsigned char* Z, const unsigned char* m);
void SM2_Signature(const Elliptic_Curve *E, User *users, Server *server, const unsigned char *Z, const unsigned char *m, SM2_sig *sig, int user_count);
int SM2_Verify(const Elliptic_Curve *E, const Point *P, const unsigned char *Z, const unsigned char *m, const SM2_sig *sig);
void SM2_free_params(Elliptic_Curve *E);
void free_user_resources(User *user);
void free_server_resources(Server *server, int user_count);
void print_BN(const char* label, const BIGNUM* num);
void print_Point(const char* label, const Point* P);
void print_SM2_sig(const char* label, const SM2_sig* P);

#endif // SM2_Multi_party_collaborative_signature
