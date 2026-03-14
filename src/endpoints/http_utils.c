#include "endpoints/http_utils.h"

#include <stdlib.h>
#include <string.h>

#define MAX_CL_SIZE 4096

enum MHD_Result send_json_response(struct MHD_Connection *connection, const char *data, int status_code) {
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(data), (void *)data, MHD_RESPMEM_MUST_COPY);
    if (!response) {
        return MHD_NO;
    }

    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(response, "Content-Type", "application/json; charset=utf-8");

    enum MHD_Result ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

void free_connection_info(connection_info **con_ptr) {
    if (!con_ptr || !*con_ptr) {
        return;
    }

    free((*con_ptr)->data);
    free(*con_ptr);
    *con_ptr = NULL;
}

enum MHD_Result fail_request(struct MHD_Connection *connection, connection_info **con_ptr, int status_code, const char *message) {
    enum MHD_Result ret = send_json_response(connection, message, status_code);
    free_connection_info(con_ptr);
    return ret;
}

body_state init_or_collect_body(const char *upload_data, size_t *upload_data_size, void **con_cls) {
    connection_info *con_info = (connection_info *)*con_cls;

    if (!con_info) {
        con_info = (connection_info *)calloc(1, sizeof(connection_info));
        if (!con_info) {
            return BODY_ALLOC_FAIL;
        }

        con_info->data = (char *)calloc(1, MAX_CL_SIZE + 1);
        if (!con_info->data) {
            free(con_info);
            return BODY_ALLOC_FAIL;
        }

        *con_cls = con_info;
        return BODY_COLLECTING;
    }

    if (*upload_data_size != 0) {
        if (con_info->data_size + *upload_data_size > MAX_CL_SIZE) {
            return BODY_TOO_LARGE;
        }

        memcpy(con_info->data + con_info->data_size, upload_data, *upload_data_size);
        con_info->data_size += *upload_data_size;
        con_info->data[con_info->data_size] = '\0';
        *upload_data_size = 0;
        return BODY_COLLECTING;
    }

    return BODY_READY;
}

json_t *parse_json_or_fail(struct MHD_Connection *connection, connection_info **con_ptr) {
    json_error_t error;
    json_t *root = json_loadb((*con_ptr)->data, (*con_ptr)->data_size, 0, &error);
    if (!root) {
        fail_request(connection, con_ptr, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid JSON format\"}");
        return NULL;
    }
    return root;
}
