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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "io.h"

struct ioex {
    struct io_base *base;
    struct io_tcp_server *server;
    bool do_exit;
};

static void ioex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

static void ioex_on_signal(int, void *);
static void ioex_on_server_event(struct io_tcp_server *,
                                 struct io_tcp_server_conn *,
                                 enum io_tcp_server_event, void *);

static struct ioex ioex;

int
main(int argc, char **argv) {
    struct c_command_line *cmdline;
    const char *host, *port_string;
    uint16_t port;

    cmdline = c_command_line_new();

    c_command_line_add_argument(cmdline, "the host to bind to", "host");
    c_command_line_add_argument(cmdline, "the port to listen on", "port");

    if (c_command_line_parse(cmdline, argc, argv) == -1)
        ioex_die("%s", c_get_error());

    host = c_command_line_argument_value(cmdline, 0);

    port_string = c_command_line_argument_value(cmdline, 1);
    if (c_parse_u16(port_string, &port, NULL) == -1)
        ioex_die("invalid port number: %s", c_get_error());

    ioex.base = io_base_new();

    if (io_base_watch_signal(ioex.base, SIGINT, ioex_on_signal, NULL) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());
    if (io_base_watch_signal(ioex.base, SIGTERM, ioex_on_signal, NULL) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());

    ioex.server = io_tcp_server_new(ioex.base, ioex_on_server_event, NULL);
    if (io_tcp_server_listen(ioex.server, host, port) == -1)
        ioex_die("cannot listen: %s", c_get_error());

    while (!ioex.do_exit) {
        if (io_base_read_events(ioex.base) == -1)
            ioex_die("cannot read events: %s", c_get_error());
    }

    io_tcp_server_delete(ioex.server);
    io_base_delete(ioex.base);

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
        io_tcp_server_stop(ioex.server);
        break;
    }
}

static void
ioex_on_server_event(struct io_tcp_server *server,
                     struct io_tcp_server_conn *conn,
                     enum io_tcp_server_event event, void *arg) {
    struct c_buffer *rbuf;
    const char *string;

    if (conn)
        rbuf = io_tcp_server_conn_rbuf(conn);

    switch (event) {
    case IO_TCP_SERVER_EVENT_SERVER_LISTENING:
        printf("server listening\n");
        break;

    case IO_TCP_SERVER_EVENT_SERVER_STOPPED:
        printf("server stopped\n");
        ioex.do_exit = true;
        break;

    case IO_TCP_SERVER_EVENT_CONN_ACCEPTED:
        printf("connection accepted\n");

        string = "hello world\n";
        if (io_tcp_server_conn_write(conn, string, strlen(string)) == -1)
            ioex_die("cannot write to connection: %s", c_get_error());
        break;

    case IO_TCP_SERVER_EVENT_CONN_CLOSED:
        printf("connection closed\n");
        break;

    case IO_TCP_SERVER_EVENT_CONN_LOST:
        printf("connection lost\n");
        break;

    case IO_TCP_SERVER_EVENT_ERROR:
        printf("error: %s\n", c_get_error());
        break;

    case IO_TCP_SERVER_EVENT_DATA_READ:
        printf("%zu bytes read\n", c_buffer_length(rbuf));
        c_buffer_clear(rbuf);

        string = "bye\n";
        if (io_tcp_server_conn_write(conn, string, strlen(string)) == -1)
            ioex_die("cannot write to connection: %s", c_get_error());

        io_tcp_server_conn_disconnect(conn);
        break;
    }
}
