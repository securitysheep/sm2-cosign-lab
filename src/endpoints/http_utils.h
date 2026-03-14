#ifndef HTTP_UTILS_H
#define HTTP_UTILS_H

#include <jansson.h>
#include <microhttpd.h>

typedef struct {
    char *data;
    size_t data_size;
} connection_info;

typedef enum {
    BODY_COLLECTING = 0,
    BODY_READY = 1,
    BODY_TOO_LARGE = 2,
    BODY_ALLOC_FAIL = 3
} body_state;

enum MHD_Result send_json_response(struct MHD_Connection *connection, const char *data, int status_code);
enum MHD_Result fail_request(struct MHD_Connection *connection, connection_info **con_ptr, int status_code, const char *message);
body_state init_or_collect_body(const char *upload_data, size_t *upload_data_size, void **con_cls);
json_t *parse_json_or_fail(struct MHD_Connection *connection, connection_info **con_ptr);
void free_connection_info(connection_info **con_ptr);

#endif
