#include "handlers.h"
#include "runtime_state.h"

#include <microhttpd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PORT 8888

static volatile sig_atomic_t g_should_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_should_stop = 1;
}

static enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection,
    const char *url, const char *method, const char *version,
    const char *upload_data, size_t *upload_data_size, void **con_cls) {
    (void)cls;
    (void)version;

    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        if (!response) {
            return MHD_NO;
        }
        MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(response, "Access-Control-Allow-Methods", "POST, GET, OPTIONS");
        MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }

    if (strcmp(method, "GET") == 0 && strcmp(url, "/health") == 0) {
        return send_json_response(connection, "{\"status\":\"ok\"}", MHD_HTTP_OK);
    }

    if (strcmp(method, "POST") != 0) {
        return send_json_response(connection, "{\"error\":\"Method not allowed\"}", MHD_HTTP_METHOD_NOT_ALLOWED);
    }

    return dispatch_post_handler(connection, url, upload_data, upload_data_size, con_cls);
}

int main(void) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_THREAD_PER_CONNECTION | MHD_USE_INTERNAL_POLLING_THREAD,
        PORT,
        NULL, NULL,
        handle_request,
        NULL,
        MHD_OPTION_END
    );

    if (!daemon) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    printf("Server running at http://localhost:%d\n", PORT);
    while (!g_should_stop) {
        sleep(1);
    }

    reset_global_state();
    MHD_stop_daemon(daemon);
    return 0;
}
