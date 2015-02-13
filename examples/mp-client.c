/*
 * Developed by Nicolas Martyanoff
 * Copyright (c) 2015 Celticom
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <signal.h>

#include "io.h"

struct ioex {
    struct io_base *base;

    struct io_mp_client *client;

    bool do_exit;
};

static void ioex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

static void ioex_on_signal(int, void *);

static void ioex_on_client_event(struct io_mp_connection *,
                                 enum io_mp_connection_event, void *, void *);

static int ioex_on_notification_string(struct io_mp_connection *,
                                       struct io_mp_msg *, void *);
static int ioex_on_response_random(struct io_mp_connection *,
                                   struct io_mp_msg *, void *);

struct ioex ioex;

int
main(int argc, char **argv) {
    struct c_command_line *cmdline;

    const char *host;
    uint16_t port;

    bool enable_ssl;
    const char *ca_certificate_path;

    host = "localhost";
    port = 5804;

    enable_ssl = false;
    ca_certificate_path = "./examples/ca.crt";

    cmdline = c_command_line_new();
    c_command_line_add_flag(cmdline, "s", "ssl", "enable ssl");

    if (c_command_line_parse(cmdline, argc, argv) == -1)
        ioex_die("%s", c_get_error());

    enable_ssl = c_command_line_is_option_set(cmdline, "ssl");

    if (enable_ssl)
        io_ssl_initialize();

    ioex.base = io_base_new();

    if (io_base_watch_signal(ioex.base, SIGINT, ioex_on_signal, NULL) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());
    if (io_base_watch_signal(ioex.base, SIGTERM, ioex_on_signal, NULL) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());

    ioex.client = io_mp_client_new(ioex.base);

    if (enable_ssl) {
        if (io_mp_client_enable_ssl(ioex.client, ca_certificate_path) == -1)
            ioex_die("cannot enable ssl: %s", c_get_error());
    }

    io_mp_client_set_event_callback(ioex.client, ioex_on_client_event, NULL);

    io_mp_client_bind_op(ioex.client, 1, IO_MP_MSG_TYPE_NOTIFICATION,
                         ioex_on_notification_string, NULL);

    if (io_mp_client_connect(ioex.client, host, port) == -1)
        ioex_die("cannot connect to %s:%u: %s", host, port, c_get_error());

    while (!ioex.do_exit) {
        if (io_base_read_events(ioex.base) == -1)
            ioex_die("cannot read events: %s", c_get_error());
    }

    io_mp_client_delete(ioex.client);

    io_base_delete(ioex.base);

    if (enable_ssl)
        io_ssl_shutdown();

    c_command_line_delete(cmdline);
    return 0;
}

void
ioex_die(const char *fmt, ...) {
    va_list ap;

    fprintf(stderr, "fatal error: ");

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    putc('\n', stderr);
    exit(1);
}

static void
ioex_on_signal(int signo, void *arg) {
    printf("signal %d received\n", signo);

    switch (signo) {
    case SIGINT:
    case SIGTERM:
        ioex.do_exit = true;
        break;
    }
}

static void
ioex_on_client_event(struct io_mp_connection *connection,
                     enum io_mp_connection_event event, void *data, void *arg) {
    switch (event) {
    case IO_MP_CONNECTION_EVENT_TRACE:
        printf("trace: %s\n", (const char *)data);
        break;

    case IO_MP_CONNECTION_EVENT_ERROR:
        fprintf(stderr, "error: %s\n", (const char *)data);
        break;

    case IO_MP_CONNECTION_EVENT_ESTABLISHED:
        printf("connection established\n");

        if (io_mp_connection_notify(connection, 1, IO_MP_MSG_FLAG_DEFAULT,
                                    "hello", 6) == -1) {
            ioex_die("cannot send message: %s", c_get_error());
        }

        if (io_mp_connection_request(connection, 2, IO_MP_MSG_FLAG_DEFAULT,
                                     NULL, 0,
                                     ioex_on_response_random, NULL) == -1) {
            ioex_die("cannot send message: %s", c_get_error());
        }
        break;

    case IO_MP_CONNECTION_EVENT_LOST:
        printf("connection lost\n");
        break;
    }
}

static int
ioex_on_notification_string(struct io_mp_connection *connection,
                            struct io_mp_msg *msg, void *arg) {
    const char *string;

    string = io_mp_msg_payload(msg, NULL);

    printf("string: %s\n", string);

    return 0;
}

static int
ioex_on_response_random(struct io_mp_connection *connection,
                        struct io_mp_msg *msg, void *arg) {
    const uint8_t *payload;
    size_t sz;
    uint32_t number;

    payload = io_mp_msg_payload(msg, &sz);
    if (sz < 4) {
        c_set_error("invalid response payload");
        return -1;
    }

    number = ((uint32_t)payload[0] << 24)
           | ((uint32_t)payload[1] << 16)
           | ((uint32_t)payload[2] <<  8)
           |  (uint32_t)payload[3];

    printf("random number: %u\n", number);

    return 0;
}
