#include "runtime_state.h"

#include <openssl/bn.h>
#include <string.h>

Elliptic_Curve *g_curve = NULL;
User *g_users = NULL;
Server g_server = {0};
Point g_group_key = {0};
int g_user_count = 0;
int g_has_group_key = 0;

void reset_global_state(void) {
    if (g_users && g_user_count > 0) {
        for (int i = 0; i < g_user_count; ++i) {
            free_user_resources(&g_users[i]);
        }
        free(g_users);
    }

    g_users = NULL;

    if (g_server.d || g_server.P.x || g_server.P.y || g_server.PK || g_server.P_group || g_server.K || g_server.eckey) {
        free_server_resources(&g_server, g_user_count);
    }
    memset(&g_server, 0, sizeof(g_server));

    if (g_curve) {
        SM2_free_params(g_curve);
        g_curve = NULL;
    }

    if (g_group_key.x) {
        BN_free(g_group_key.x);
        g_group_key.x = NULL;
    }
    if (g_group_key.y) {
        BN_free(g_group_key.y);
        g_group_key.y = NULL;
    }

    g_user_count = 0;
    g_has_group_key = 0;
}
