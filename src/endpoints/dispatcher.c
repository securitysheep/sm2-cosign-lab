#include "handlers.h"
#include "endpoints/http_utils.h"
#include <string.h>

enum MHD_Result handle_init_endpoint(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size, void **con_cls);
enum MHD_Result handle_group_endpoint(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size, void **con_cls);
enum MHD_Result handle_sign_endpoint(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size, void **con_cls);
enum MHD_Result handle_verify_endpoint(struct MHD_Connection *connection, const char *upload_data, size_t *upload_data_size, void **con_cls);

enum MHD_Result dispatch_post_handler(struct MHD_Connection *connection,
    const char *url,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls) {
    if (strcmp(url, "/init") == 0) {
        return handle_init_endpoint(connection, upload_data, upload_data_size, con_cls);
    }
    if (strcmp(url, "/gen-group-key") == 0) {
        return handle_group_endpoint(connection, upload_data, upload_data_size, con_cls);
    }
    if (strcmp(url, "/sign") == 0) {
        return handle_sign_endpoint(connection, upload_data, upload_data_size, con_cls);
    }
    if (strcmp(url, "/verify") == 0) {
        return handle_verify_endpoint(connection, upload_data, upload_data_size, con_cls);
    }

    return send_json_response(connection, "{\"error\":\"Not found\"}", MHD_HTTP_NOT_FOUND);
}
