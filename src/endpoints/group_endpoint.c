#include "endpoints/http_utils.h"
#include "runtime_state.h"

#include <openssl/bn.h>
#include <stdlib.h>

enum MHD_Result handle_group_endpoint(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size, void **con_cls) {
    body_state state = init_or_collect_body(upload_data, upload_data_size, con_cls);
    if (state == BODY_COLLECTING) {
        return MHD_YES;
    }
    if (state == BODY_ALLOC_FAIL) {
        return send_json_response(connection, "{\"error\":\"Memory allocation failed\"}", MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
    if (state == BODY_TOO_LARGE) {
        connection_info *overflow_info = (connection_info *)*con_cls;
        return fail_request(connection, &overflow_info, MHD_HTTP_CONTENT_TOO_LARGE, "{\"error\":\"Request body too large\"}");
    }

    connection_info *con_info = (connection_info *)*con_cls;
    json_t *root = parse_json_or_fail(connection, &con_info);
    if (!root) {
        *con_cls = NULL;
        return MHD_YES;
    }

    if (!g_curve || !g_users || g_user_count <= 0) {
        json_decref(root);
        return fail_request(connection, &con_info, MHD_HTTP_BAD_REQUEST, "{\"error\":\"System not initialized\"}");
    }

    if (g_group_key.x) {
        BN_free(g_group_key.x);
        g_group_key.x = NULL;
    }
    if (g_group_key.y) {
        BN_free(g_group_key.y);
        g_group_key.y = NULL;
    }

    g_group_key.x = BN_new();
    g_group_key.y = BN_new();
    if (!g_group_key.x || !g_group_key.y) {
        json_decref(root);
        return fail_request(connection, &con_info, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Memory allocation failed\"}");
    }

    if (SM2_gen_group_pubkey(g_curve, g_users, &g_server, &g_group_key, g_user_count) != 0) {
        json_decref(root);
        g_has_group_key = 0;
        return fail_request(connection, &con_info, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Group key gen failed\"}");
    }

    g_has_group_key = 1;

    json_t *response = json_object();
    json_t *users_array = json_array();

    for (int i = 0; i < g_user_count; ++i) {
        json_t *user = json_object();
        char *gx = BN_bn2hex(g_users[i].P_group.x);
        char *gy = BN_bn2hex(g_users[i].P_group.y);

        json_object_set_new(user, "group_public_x", json_string(gx ? gx : ""));
        json_object_set_new(user, "group_public_y", json_string(gy ? gy : ""));
        json_array_append_new(users_array, user);

        if (gx) OPENSSL_free(gx);
        if (gy) OPENSSL_free(gy);
    }

    json_object_set_new(response, "users", users_array);

    json_t *group_public = json_object();
    char *pmx = BN_bn2hex(g_group_key.x);
    char *pmy = BN_bn2hex(g_group_key.y);
    json_object_set_new(group_public, "x", json_string(pmx ? pmx : ""));
    json_object_set_new(group_public, "y", json_string(pmy ? pmy : ""));
    json_object_set_new(response, "group_public", group_public);

    if (pmx) OPENSSL_free(pmx);
    if (pmy) OPENSSL_free(pmy);

    char *response_str = json_dumps(response, JSON_COMPACT);
    json_decref(response);
    json_decref(root);

    if (!response_str) {
        return fail_request(connection, &con_info, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Failed to generate response\"}");
    }

    enum MHD_Result ret = send_json_response(connection, response_str, MHD_HTTP_OK);
    free(response_str);
    free_connection_info(&con_info);
    *con_cls = NULL;
    return ret;
}
