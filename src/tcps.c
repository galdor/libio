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

#include "internal.h"

/* ------------------------------------------------------------------------
 *  Connection
 * ------------------------------------------------------------------------ */
static int io_tcpsc_watch(struct io_tcpsc *, uint32_t);
static void io_tcpsc_signal_event(struct io_tcpsc *, enum io_tcps_event);
static void io_tcpsc_signal_error(struct io_tcpsc *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

static void io_tcpsc_on_event(int, uint32_t, void *);

struct io_tcpsc *
io_tcpsc_new(struct io_tcps *server, int sock) {
    struct io_tcpsc *connection;

    connection = c_malloc0(sizeof(struct io_tcpsc));

    connection->state = IO_TCPSC_STATE_CONNECTED;

    connection->sock = sock;

    connection->rbuf = c_buffer_new();
    connection->wbuf = c_buffer_new();

    connection->server = server;

    return connection;
}

void
io_tcpsc_delete(struct io_tcpsc *connection) {
    if (!connection)
        return;

    c_buffer_delete(connection->rbuf);
    c_buffer_delete(connection->wbuf);

    c_free0(connection, sizeof(struct io_tcpsc));
}

void
io_tcpsc_discard(struct io_tcpsc *connection) {
    assert(connection->state == IO_TCPSC_STATE_DISCONNECTED);

    io_tcps_remove_connection(connection->server, connection);
    io_tcpsc_delete(connection);
}

void
io_tcpsc_close_discard(struct io_tcpsc *connection) {
    io_tcpsc_close(connection);
    io_tcpsc_signal_event(connection, IO_TCPS_EVENT_CONNECTION_CLOSED);

    io_tcpsc_discard(connection);
}

void
io_tcpsc_disconnect(struct io_tcpsc *connection) {
    assert(connection->state == IO_TCPSC_STATE_CONNECTED);

    if (c_buffer_length(connection->wbuf) == 0) {
        io_tcpsc_close_discard(connection);
        return;
    }

    if (shutdown(connection->sock, SHUT_RD) == -1) {
        io_tcpsc_signal_error(connection, "cannot shutdown socket: %s",
                              strerror(errno));

        io_tcpsc_close_discard(connection);
        return;
    }

    if (io_tcpsc_watch(connection, IO_EVENT_FD_WRITE) == -1) {
        io_tcpsc_signal_error(connection, "%s", c_get_error());
        io_tcpsc_close_discard(connection);
        return;
    }

    connection->state = IO_TCPSC_STATE_DISCONNECTING;
}

void 
io_tcpsc_close(struct io_tcpsc *connection) {
    if (connection->state == IO_TCPSC_STATE_DISCONNECTED)
        return;

    if (io_base_unwatch_fd(connection->server->base, connection->sock) == -1) {
        io_tcpsc_signal_error(connection, "cannot unwatch socket: %s",
                              c_get_error());
    }

    close(connection->sock);
    connection->sock = -1;

    connection->state = IO_TCPSC_STATE_DISCONNECTED;
}

int
io_tcpsc_write(struct io_tcpsc *connection, const void *data, size_t sz) {
    assert(connection->state == IO_TCPSC_STATE_CONNECTED);

    if (sz == 0)
        return 0;

    c_buffer_add(connection->wbuf, data, sz);

    return io_tcpsc_watch(connection, IO_EVENT_FD_READ | IO_EVENT_FD_WRITE);
}

struct c_buffer *
io_tcpsc_rbuf(const struct io_tcpsc *connection) {
    return connection->rbuf;
}

static int
io_tcpsc_watch(struct io_tcpsc *connection, uint32_t events) {
    if (io_base_watch_fd(connection->server->base, connection->sock, events,
                         io_tcpsc_on_event, connection) == -1) {
        c_set_error("cannot watch socket: %s", c_get_error());
        return -1;
    }

    return 0;
}

static void
io_tcpsc_signal_event(struct io_tcpsc *connection, enum io_tcps_event event) {
    struct io_tcps *server;

    server = connection->server;

    if (!server->event_cb)
        return;

    server->event_cb(server, connection, event, server->event_cb_arg);
}

static void
io_tcpsc_signal_error(struct io_tcpsc *connection, const char *fmt, ...) {
    char buf[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    c_set_error("%s", buf);
    io_tcpsc_signal_event(connection, IO_TCPS_EVENT_ERROR);
}

static void
io_tcpsc_on_event(int sock, uint32_t events, void *arg) {
    struct io_tcpsc *connection;

    connection = arg;

    assert(connection->state == IO_TCPSC_STATE_CONNECTED
        || connection->state == IO_TCPSC_STATE_DISCONNECTING);

    if (events & IO_EVENT_FD_READ) {
        ssize_t ret;

        ret = c_buffer_read(connection->rbuf, connection->sock, BUFSIZ);
        if (ret == -1) {
            io_tcpsc_signal_error(connection, "cannot read socket: %s",
                                  c_get_error());
            io_tcpsc_close_discard(connection);
            return;
        } else if (ret == 0) {
            io_tcpsc_close_discard(connection);
            return;
        }

        io_tcpsc_signal_event(connection, IO_TCPS_EVENT_DATA_READ);
        if (connection->state == IO_TCPS_EVENT_CONNECTION_CLOSED) {
            io_tcpsc_discard(connection);
            return;
        }
    }

    if (events & IO_EVENT_FD_WRITE) {
        if (c_buffer_write(connection->wbuf, connection->sock) == -1) {
            io_tcpsc_signal_error(connection, "cannot write socket: %s",
                                  strerror(errno));
            io_tcpsc_close_discard(connection);
            return;
        }

        if (c_buffer_length(connection->wbuf) == 0) {
            if (connection->state == IO_TCPSC_STATE_DISCONNECTING) {
                io_tcpsc_close_discard(connection);
                return;
            }

            if (io_tcpsc_watch(connection, IO_EVENT_FD_READ) == -1) {
                io_tcpsc_signal_error(connection, "%s", c_get_error());
                io_tcpsc_close_discard(connection);
                return;
            }
        }
    }
}

/* ------------------------------------------------------------------------
 *  Server
 * ------------------------------------------------------------------------ */
static void io_tcps_signal_event(struct io_tcps *, enum io_tcps_event);
static void io_tcps_signal_error(struct io_tcps *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

static void io_tcps_on_event(int, uint32_t, void *);

struct io_tcps *
io_tcps_new(struct io_base *base, io_tcps_event_cb cb, void *cb_arg) {
    struct io_tcps *server;

    server = c_malloc0(sizeof(struct io_tcps));

    server->state = IO_TCPS_STATE_STOPPED;

    server->connections = c_queue_new();

    server->event_cb = cb;
    server->event_cb_arg = cb_arg;

    server->base = base;

    return server;
}

void
io_tcps_delete(struct io_tcps *server) {
    if (!server)
        return;

    c_free(server->host);

    c_free(server->socks);

    c_queue_delete(server->connections);

    c_free0(server, sizeof(struct io_tcps));
}

int
io_tcps_listen(struct io_tcps *server, const char *host, uint16_t port) {
    struct io_address *addrs;
    size_t nb_addrs;
    int *socks;

    assert(server->state == IO_TCPS_STATE_STOPPED);

    if (io_address_resolve(host, port, AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP,
                           &addrs, &nb_addrs) == -1) {
        c_set_error("cannot resolve address: %s", c_get_error());
        return -1;
    }

    socks = c_calloc(nb_addrs, sizeof(int));

    for (size_t i = 0; i < nb_addrs; i++) {
        struct io_address *addr;
        int sock, opt;

        addr = addrs + i;

        sock = socket(io_address_family(addr), SOCK_STREAM, IPPROTO_TCP);
        if (sock == -1) {
            c_set_error("cannot create socket: %s", strerror(errno));
            goto error;
        }

        opt = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) == -1) {
            c_set_error("cannot set SO_REUSEADDR: %s", strerror(errno));
            close(sock);
            goto error;
        }

        if (bind(sock, io_address_sockaddr(addr),
                 io_address_length(addr)) == -1) {
            c_set_error("cannot bind socket: %s", c_get_error());
            close(sock);
            goto error;
        }

        if (listen(sock, 10) == -1) {
            c_set_error("cannot listen on socket: %s", c_get_error());
            close(sock);
            goto error;
        }

        if (io_base_watch_fd(server->base, sock, IO_EVENT_FD_READ,
                             io_tcps_on_event, server) == -1) {
            c_set_error("cannot watch socket: %s", c_get_error());
            close(sock);
            goto error;
        }

        socks[i] = sock;
    }

    c_free(server->host);
    server->host = c_strdup(host);
    server->port = port;

    server->nb_socks = nb_addrs;
    server->socks = socks;

    server->state = IO_TCPS_STATE_LISTENING;

    io_tcps_signal_event(server, IO_TCPS_EVENT_SERVER_LISTENING);

    c_free(addrs);
    return 0;

error:
    c_free(socks);
    c_free(addrs);
    return -1;
}

void
io_tcps_stop(struct io_tcps *server) {
    struct c_queue_entry *entry;

    assert(server->state == IO_TCPS_STATE_LISTENING);

    for (size_t i = 0; i < server->nb_socks; i++) {
        int sock;

        sock = server->socks[i];

        if (io_base_unwatch_fd(server->base, sock) == -1) {
            io_tcps_signal_error(server, "cannot unwatch socket: %s",
                                 c_get_error());
        }
    }

    /* The proper way would be disconnect all connections and wait for the
     * last one to be closed, then close the server. Infortunately, it means
     * checking whether the connection list is empty or not each time a
     * connection is removed. I have to do it one day... */

    entry = c_queue_first_entry(server->connections);
    while (entry) {
        struct io_tcpsc *connection;

        connection = c_queue_entry_value(entry);

        io_tcpsc_close(connection);
        io_tcpsc_signal_event(connection, IO_TCPS_EVENT_CONNECTION_CLOSED);
        io_tcpsc_delete(connection);

        entry = c_queue_entry_next(entry);
    }

    c_queue_clear(server->connections);

    io_tcps_close(server);
    io_tcps_signal_event(server, IO_TCPS_EVENT_SERVER_STOPPED);
}

void
io_tcps_close(struct io_tcps *server) {
    struct c_queue_entry *entry;

    if (server->state == IO_TCPS_STATE_STOPPED)
        return;

    for (size_t i = 0; i < server->nb_socks; i++) {
        close(server->socks[i]);
        server->socks[i] = -1;
    }

    entry = c_queue_first_entry(server->connections);
    while (entry) {
        struct io_tcpsc *connection;

        connection = c_queue_entry_value(entry);

        io_tcpsc_close(connection);
        io_tcpsc_delete(connection);

        entry = c_queue_entry_next(entry);
    }

    c_queue_clear(server->connections);

    server->state = IO_TCPS_STATE_STOPPED;
}

void
io_tcps_add_connection(struct io_tcps *server, struct io_tcpsc *connection) {
    assert(!connection->queue_entry);

    c_queue_push(server->connections, connection);
    connection->queue_entry = c_queue_last_entry(server->connections);
}

void
io_tcps_remove_connection(struct io_tcps *server, struct io_tcpsc *connection) {
    assert(connection->queue_entry);

    c_queue_remove_entry(server->connections, connection->queue_entry);
    c_queue_entry_delete(connection->queue_entry);
    connection->queue_entry = NULL;
}

static void
io_tcps_signal_event(struct io_tcps *server, enum io_tcps_event event) {
    if (!server->event_cb)
        return;

    server->event_cb(server, NULL, event, server->event_cb_arg);
}

static void
io_tcps_signal_error(struct io_tcps *server, const char *fmt, ...) {
    char buf[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    c_set_error("%s", buf);
    io_tcps_signal_event(server, IO_TCPS_EVENT_ERROR);
}

static void
io_tcps_on_event(int sock, uint32_t events, void *arg) {
    struct io_tcps *server;
    struct io_tcpsc *connection;
    struct sockaddr_storage ss;
    socklen_t ss_len;
    struct io_address addr;
    int csock;

    server = arg;

    assert(server->state == IO_TCPS_STATE_LISTENING);
    assert(events & IO_EVENT_FD_READ);

    ss_len = sizeof(struct sockaddr_storage);
    csock = accept(sock, (struct sockaddr *)&ss, &ss_len);
    if (csock == -1) {
        io_tcps_signal_error(server, "cannot accept connection: %s",
                             c_get_error());
        return;
    }

    if (io_address_init_from_sockaddr_storage(&addr, &ss) == -1) {
        io_tcps_signal_error(server, "cannot initialize connection address: %s",
                             c_get_error());
        close(sock);
    }

    connection = io_tcpsc_new(server, csock);
    connection->addr = addr;

    if (io_tcpsc_watch(connection, IO_EVENT_FD_READ) == -1) {
        io_tcpsc_signal_error(connection, "%s", c_get_error());

        io_tcpsc_close(connection);
        io_tcpsc_signal_event(connection, IO_TCPS_EVENT_CONNECTION_CLOSED);

        io_tcpsc_delete(connection);
        return;
    }

    io_tcps_add_connection(server, connection);

    io_tcpsc_signal_event(connection, IO_TCPS_EVENT_CONNECTION_ACCEPTED);
    if (connection->state == IO_TCPS_EVENT_CONNECTION_CLOSED) {
        io_tcpsc_discard(connection);
        return;
    }
}
