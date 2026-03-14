#include "endpoints/http_utils.h"
#include "runtime_state.h"

#include <openssl/bn.h>
#include <stdlib.h>

enum MHD_Result handle_verify_endpoint(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size, void **con_cls) {
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
    const char *r = json_string_value(json_object_get(root, "r"));
    const char *s = json_string_value(json_object_get(root, "s"));

    if (!message || !r || !s || !g_curve || !g_users || !g_has_group_key) {
        json_decref(root);
        return fail_request(connection, &con_info, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid verify request\"}");
    }

    SM2_sig sig = {.r = NULL, .s = NULL};
    if (!BN_hex2bn(&sig.r, r) || !BN_hex2bn(&sig.s, s)) {
        if (sig.r) BN_free(sig.r);
        if (sig.s) BN_free(sig.s);
        json_decref(root);
        return fail_request(connection, &con_info, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid signature parameters\"}");
    }

    unsigned char Z[SM3_DIGEST_LENGTH] = {0};
    params_hash(g_curve, &g_users[0], Z);
    int valid = SM2_Verify(g_curve, &g_group_key, Z, (const unsigned char *)message, &sig);

    BN_free(sig.r);
    BN_free(sig.s);

    json_t *response = json_object();
    json_object_set_new(response, "valid", json_boolean(valid));
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
