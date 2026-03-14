#include "endpoints/http_utils.h"
#include "runtime_state.h"

#include <openssl/bn.h>
#include <stdlib.h>

enum MHD_Result handle_sign_endpoint(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size, void **con_cls) {
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

    const char *message = json_string_value(json_object_get(root, "message"));
    if (!message || !g_curve || !g_users || g_user_count <= 0) {
        json_decref(root);
        return fail_request(connection, &con_info, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid sign request\"}");
    }

    unsigned char Z[SM3_DIGEST_LENGTH] = {0};
    params_hash(g_curve, &g_users[0], Z);

    SM2_sig sig = {.r = BN_new(), .s = BN_new()};
    if (!sig.r || !sig.s) {
        if (sig.r) BN_free(sig.r);
        if (sig.s) BN_free(sig.s);
        json_decref(root);
        return fail_request(connection, &con_info, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Memory allocation failed\"}");
    }

    SM2_Signature(g_curve, g_users, &g_server, Z, (const unsigned char *)message, &sig, g_user_count);

    json_t *response = json_object();
    json_t *kg_array = json_array();

    for (int i = 0; i < g_user_count; ++i) {
        json_t *kg = json_object();
        char *kgx = BN_bn2hex(g_users[i].KG.x);
        char *kgy = BN_bn2hex(g_users[i].KG.y);

        json_object_set_new(kg, "x", json_string(kgx ? kgx : ""));
        json_object_set_new(kg, "y", json_string(kgy ? kgy : ""));
        json_array_append_new(kg_array, kg);

        if (kgx) OPENSSL_free(kgx);
        if (kgy) OPENSSL_free(kgy);
    }

    json_object_set_new(response, "kg", kg_array);

    char *r = BN_bn2hex(sig.r);
    char *s = BN_bn2hex(sig.s);
    json_object_set_new(response, "r", json_string(r ? r : ""));
    json_object_set_new(response, "s", json_string(s ? s : ""));

    if (r) OPENSSL_free(r);
    if (s) OPENSSL_free(s);

    char *response_str = json_dumps(response, JSON_COMPACT);

    BN_free(sig.r);
    BN_free(sig.s);
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
