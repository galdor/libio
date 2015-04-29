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

#include <unistd.h>

#include "io.h"

struct ioex {
    struct io_base *base;
    struct io_tcpc *client;
    bool do_exit;
};

static void ioex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

static void ioex_on_signal(int, void *);
static void ioex_on_client_event(struct io_tcpc *, enum io_tcpc_event, void *);

static struct ioex ioex;

int
main(int argc, char **argv) {
    struct c_command_line *cmdline;
    const char *host, *port_string;
    uint16_t port;

    cmdline = c_command_line_new();

    c_command_line_add_argument(cmdline, "the host to connect to", "host");
    c_command_line_add_argument(cmdline, "the port to connect to", "port");

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

    ioex.client = io_tcpc_new(ioex.base, ioex_on_client_event, NULL);
    if (io_tcpc_connect(ioex.client, host, port) == -1)
        ioex_die("cannot connect client: %s", c_get_error());

    while (!ioex.do_exit) {
        if (io_base_read_events(ioex.base) == -1)
            ioex_die("cannot read events: %s", c_get_error());
    }

    io_tcpc_delete(ioex.client);
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
        io_tcpc_disconnect(ioex.client);
        break;
    }
}

static void
ioex_on_client_event(struct io_tcpc *client, enum io_tcpc_event event,
                     void *arg) {
    struct c_buffer *rbuf;
    const char *string;

    rbuf = io_tcpc_rbuf(client);

    switch (event) {
    case IO_TCPC_EVENT_CONNECTION_ESTABLISHED:
        printf("connection established\n");

        string = "hello world\n";
        io_tcpc_write(client, string, strlen(string));
        break;

    case IO_TCPC_EVENT_CONNECTION_CLOSED:
        printf("connection closed\n");
        ioex.do_exit = true;
        break;

    case IO_TCPC_EVENT_CONNECTION_LOST:
        printf("connection lost\n");
        ioex.do_exit = true;
        break;

    case IO_TCPC_EVENT_ERROR:
        printf("error: %s\n", c_get_error());
        break;

    case IO_TCPC_EVENT_DATA_READ:
        printf("%zu bytes read\n", c_buffer_length(rbuf));
        c_buffer_clear(rbuf);

        string = "bye\n";
        io_tcpc_write(client, string, strlen(string));

        io_tcpc_disconnect(client);
        break;
    }
}