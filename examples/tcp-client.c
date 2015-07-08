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
    struct io_tcp_client *client;
    bool do_exit;
};

static void ioex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

static void ioex_on_signal(int, void *);
static void ioex_on_client_event(struct io_tcp_client *,
                                 enum io_tcp_client_event, void *);

static struct ioex ioex;

int
main(int argc, char **argv) {
    struct c_command_line *cmdline;
    const char *host, *port_string;
    uint16_t port;
    bool use_ssl;
    const char *ca_cert, *cert, *key;

    cmdline = c_command_line_new();

    c_command_line_add_flag(cmdline, "s", "ssl", "use ssl");
    c_command_line_add_option(cmdline, NULL, "ca-cert",
                              "the ssl ca certificate", "path", NULL);
    c_command_line_add_option(cmdline, NULL, "cert",
                              "the ssl client certificate", "path", NULL);
    c_command_line_add_option(cmdline, NULL, "key",
                              "the ssl private key", "path", NULL);

    c_command_line_add_argument(cmdline, "the host to connect to", "host");
    c_command_line_add_argument(cmdline, "the port to connect to", "port");

    if (c_command_line_parse(cmdline, argc, argv) == -1)
        ioex_die("%s", c_get_error());

    host = c_command_line_argument_value(cmdline, 0);

    port_string = c_command_line_argument_value(cmdline, 1);
    if (c_parse_u16(port_string, &port, NULL) == -1)
        ioex_die("invalid port number: %s", c_get_error());

    use_ssl = c_command_line_is_option_set(cmdline, "ssl");
    if (use_ssl) {
        ca_cert = c_command_line_option_value(cmdline, "ca-cert");
        cert = c_command_line_option_value(cmdline, "cert");
        key = c_command_line_option_value(cmdline, "key");
    }

    if (use_ssl)
        io_ssl_initialize();

    ioex.base = io_base_new();

    if (io_base_watch_signal(ioex.base, SIGINT, ioex_on_signal, NULL) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());
    if (io_base_watch_signal(ioex.base, SIGTERM, ioex_on_signal, NULL) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());

    ioex.client = io_tcp_client_new(ioex.base, ioex_on_client_event, NULL);

    if (use_ssl) {
        struct io_ssl_client_cfg cfg;

        memset(&cfg, 0, sizeof(struct io_ssl_client_cfg));

        cfg.ca_cert_path = ca_cert;
        cfg.cert_path = cert;
        cfg.key_path = key;

        if (io_tcp_client_enable_ssl(ioex.client, &cfg) == -1)
            ioex_die("cannot enable ssl: %s", c_get_error());
    }

    if (io_tcp_client_connect(ioex.client, host, port) == -1)
        ioex_die("cannot connect client: %s", c_get_error());

    while (!ioex.do_exit) {
        if (io_base_read_events(ioex.base) == -1)
            ioex_die("cannot read events: %s", c_get_error());
    }

    io_tcp_client_delete(ioex.client);
    io_base_delete(ioex.base);

    if (use_ssl)
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
        io_tcp_client_disconnect(ioex.client);
        break;
    }
}

static void
ioex_on_client_event(struct io_tcp_client *client,
                     enum io_tcp_client_event event, void *arg) {
    struct c_buffer *rbuf;
    const char *string;

    rbuf = io_tcp_client_rbuf(client);

    switch (event) {
    case IO_TCP_CLIENT_EVENT_CONN_ESTABLISHED:
        printf("connection established\n");

        string = "hello world\n";
        io_tcp_client_write(client, string, strlen(string));
        break;

    case IO_TCP_CLIENT_EVENT_CONN_FAILED:
        printf("connection failed\n");
        ioex.do_exit = true;
        break;

    case IO_TCP_CLIENT_EVENT_CONN_CLOSED:
        printf("connection closed\n");
        ioex.do_exit = true;
        break;

    case IO_TCP_CLIENT_EVENT_ERROR:
        printf("error: %s\n", c_get_error());
        break;

    case IO_TCP_CLIENT_EVENT_DATA_READ:
        printf("%zu bytes read\n", c_buffer_length(rbuf));
        c_buffer_clear(rbuf);

        string = "bye\n";
        io_tcp_client_write(client, string, strlen(string));

        io_tcp_client_disconnect(client);
        break;
    }
}
