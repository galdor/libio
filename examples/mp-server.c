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

    struct io_mp_server *server;

    bool do_exit;
};

static void ioex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

static void ioex_on_signal(int, void *);

static void ioex_on_server_event(struct io_mp_connection *,
                                 enum io_mp_connection_event, void *);

static void ioex_on_notification_string(struct io_mp_connection *,
                                        const struct io_mp_msg *, void *);
static void ioex_on_request_random(struct io_mp_connection *,
                                   const struct io_mp_msg *, void *);

struct ioex ioex;

int
main(int argc, char **argv) {
    const char *iface;
    uint16_t port;

    iface = "lo";
    port = 5804;

    ioex.base = io_base_new();

    if (io_base_watch_signal(ioex.base, SIGINT, ioex_on_signal, NULL) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());
    if (io_base_watch_signal(ioex.base, SIGTERM, ioex_on_signal, NULL) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());

    ioex.server = io_mp_server_new(ioex.base);

    io_mp_server_set_event_callback(ioex.server, ioex_on_server_event);

    io_mp_server_bind_op(ioex.server, 1, IO_MP_MSG_TYPE_NOTIFICATION,
                         ioex_on_notification_string, NULL);
    io_mp_server_bind_op(ioex.server, 2, IO_MP_MSG_TYPE_REQUEST,
                         ioex_on_request_random, NULL);

    if (io_mp_server_listen(ioex.server, iface, port) == -1) {
        ioex_die("cannot listen on interface %s port %u: %s",
                 iface, port, c_get_error());
    }

    while (!ioex.do_exit) {
        if (io_base_read_events(ioex.base) == -1)
            ioex_die("cannot read events: %s", c_get_error());
    }

    io_mp_server_delete(ioex.server);
    io_base_delete(ioex.base);
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
ioex_on_server_event(struct io_mp_connection *connection,
                     enum io_mp_connection_event event, void *data) {
    switch (event) {
    case IO_MP_CONNECTION_EVENT_TRACE:
        printf("trace: %s\n", (const char *)data);
        break;

    case IO_MP_CONNECTION_EVENT_ERROR:
        fprintf(stderr, "error: %s\n", (const char *)data);
        break;

    case IO_MP_CONNECTION_EVENT_ESTABLISHED:
        printf("connection established\n");

        if (io_mp_connection_send_notification(connection,
                                               1, IO_MP_MSG_FLAG_DEFAULT,
                                               "hello", 6) == -1) {
            ioex_die("cannot send message: %s", c_get_error());
        }
        break;

    case IO_MP_CONNECTION_EVENT_LOST:
        printf("connection lost\n");
        break;
    }
}

static void
ioex_on_notification_string(struct io_mp_connection *connection,
                            const struct io_mp_msg *msg, void *arg) {
    const char *string;

    string = io_mp_msg_payload(msg, NULL);

    printf("string: %s\n", string);
}

static void
ioex_on_request_random(struct io_mp_connection *connection,
                       const struct io_mp_msg *msg, void *arg) {
    uint32_t number;
    uint8_t payload[4];

    number = (uint32_t)(random() % UINT32_MAX);

    payload[0] = (number & 0xff000000) >> 24;
    payload[1] = (number & 0x00ff0000) >> 16;
    payload[2] = (number & 0x0000ff00) >>  8;
    payload[3] =  number & 0x000000ff;

    if (io_mp_connection_send_response(connection,
                                       msg, IO_MP_MSG_FLAG_DEFAULT,
                                       payload, sizeof(payload)) == -1) {
    }
}
