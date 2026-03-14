#ifndef HANDLERS_H
#define HANDLERS_H

#include <microhttpd.h>

enum MHD_Result send_json_response(struct MHD_Connection *connection, const char *data, int status_code);
enum MHD_Result dispatch_post_handler(struct MHD_Connection *connection,
    const char *url,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls);

#endif
