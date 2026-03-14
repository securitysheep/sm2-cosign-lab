#include "endpoints/http_utils.h"
#include "runtime_state.h"

#include <openssl/bn.h>
#include <stdlib.h>

enum MHD_Result handle_init_endpoint(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size, void **con_cls) {
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

    json_t *count_obj = json_object_get(root, "user_count");
    int requested_count = (int)json_integer_value(count_obj);
    if (!json_is_integer(count_obj) || requested_count <= 0) {
        json_decref(root);
        return fail_request(connection, &con_info, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid user count\"}");
    }

    reset_global_state();

    g_users = (User *)calloc((size_t)requested_count, sizeof(User));
    if (!g_users) {
        json_decref(root);
        return fail_request(connection, &con_info, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Memory allocation failed\"}");
    }

    g_curve = SM2_init_EC_params();
    if (!g_curve) {
        json_decref(root);
        reset_global_state();
        return fail_request(connection, &con_info, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Curve init failed\"}");
    }

    if (SM2_init_system(g_users, &g_server, requested_count) != 0) {
        json_decref(root);
        reset_global_state();
        return fail_request(connection, &con_info, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"System init failed\"}");
    }

    g_user_count = requested_count;

    json_t *response = json_object();
    json_t *server_info = json_object();
    json_t *users_array = json_array();

    char *d = BN_bn2hex(g_server.d);
    char *px = BN_bn2hex(g_server.P.x);
    char *py = BN_bn2hex(g_server.P.y);

    json_object_set_new(server_info, "private", json_string(d ? d : ""));
    json_object_set_new(server_info, "px", json_string(px ? px : ""));
    json_object_set_new(server_info, "py", json_string(py ? py : ""));
    json_object_set_new(response, "server", server_info);

    if (d) OPENSSL_free(d);
    if (px) OPENSSL_free(px);
    if (py) OPENSSL_free(py);

    for (int i = 0; i < g_user_count; ++i) {
        json_t *user = json_object();
        char *ud = BN_bn2hex(g_users[i].d);
        char *upx = BN_bn2hex(g_users[i].P.x);
        char *upy = BN_bn2hex(g_users[i].P.y);

        json_object_set_new(user, "private", json_string(ud ? ud : ""));
        json_object_set_new(user, "px", json_string(upx ? upx : ""));
        json_object_set_new(user, "py", json_string(upy ? upy : ""));
        json_array_append_new(users_array, user);

        if (ud) OPENSSL_free(ud);
        if (upx) OPENSSL_free(upx);
        if (upy) OPENSSL_free(upy);
    }

    json_object_set_new(response, "users", users_array);

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
