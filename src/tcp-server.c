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
static int io_tcp_server_conn_watch(struct io_tcp_server_conn *, uint32_t);
static void io_tcp_server_conn_signal_event(struct io_tcp_server_conn *,
                                            enum io_tcp_server_event);
static void
io_tcp_server_conn_signal_error(struct io_tcp_server_conn *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

static void io_tcp_server_conn_on_connected(struct io_tcp_server_conn *);

static void io_tcp_server_conn_on_event_ssl_accepting(int, uint32_t, void *);
static void io_tcp_server_conn_on_event(int, uint32_t, void *);

struct io_tcp_server_conn *
io_tcp_server_conn_new(struct io_tcp_server *server, int sock) {
    struct io_tcp_server_conn *conn;

    conn = c_malloc0(sizeof(struct io_tcp_server_conn));

    conn->state = IO_TCP_SERVER_CONN_STATE_DISCONNECTED;

    conn->sock = sock;

    conn->rbuf = c_buffer_new();
    conn->wbuf = c_buffer_new();

    conn->server = server;

    return conn;
}

void
io_tcp_server_conn_delete(struct io_tcp_server_conn *conn) {
    if (!conn)
        return;

    c_buffer_delete(conn->rbuf);
    c_buffer_delete(conn->wbuf);

    c_free0(conn, sizeof(struct io_tcp_server_conn));
}

int
io_tcp_server_conn_ssl_accept(struct io_tcp_server_conn *conn) {
    struct io_tcp_server *server;
    int ret;

    assert(conn->state == IO_TCP_SERVER_CONN_STATE_SSL_ACCEPTING);
    assert(conn->uses_ssl);

    server = conn->server;

    ret = SSL_accept(conn->ssl);
    if (ret != 1) {
        int err;

        err = SSL_get_error(conn->ssl, ret);

        switch (err) {
        case SSL_ERROR_WANT_READ:
            if (io_base_watch_fd(server->base, conn->sock, IO_EVENT_FD_READ,
                                 io_tcp_server_conn_on_event_ssl_accepting,
                                 conn) == -1) {
                c_set_error("cannot watch socket: %s", c_get_error());
                return -1;
            }
            break;

        case SSL_ERROR_WANT_WRITE:
            if (io_base_watch_fd(server->base, conn->sock, IO_EVENT_FD_WRITE,
                                 io_tcp_server_conn_on_event_ssl_accepting,
                                 conn) == -1) {
                c_set_error("cannot watch socket: %s", c_get_error());
                return -1;
            }
            break;

        default:
            c_set_error("cannot accept ssl connection: %s",
                        io_ssl_get_error());
            return -1;
        }

        return 0;
    }

    conn->state = IO_TCP_SERVER_CONN_STATE_CONNECTED;
    return 0;
}

void
io_tcp_server_conn_discard(struct io_tcp_server_conn *conn) {
    assert(conn->state == IO_TCP_SERVER_CONN_STATE_DISCONNECTED);

    io_tcp_server_remove_conn(conn->server, conn);
    io_tcp_server_conn_delete(conn);
}

void
io_tcp_server_conn_close_discard(struct io_tcp_server_conn *conn) {
    io_tcp_server_conn_close(conn);
    io_tcp_server_conn_signal_event(conn, IO_TCP_SERVER_EVENT_CONN_CLOSED);

    io_tcp_server_conn_discard(conn);
}

void
io_tcp_server_conn_disconnect(struct io_tcp_server_conn *conn) {
    if (conn->state != IO_TCP_SERVER_CONN_STATE_CONNECTED)
        return;

    if (c_buffer_length(conn->wbuf) == 0) {
        io_tcp_server_conn_close(conn);
        io_tcp_server_conn_signal_event(conn, IO_TCP_SERVER_EVENT_CONN_CLOSED);
        return;
    }

    if (shutdown(conn->sock, SHUT_RD) == -1) {
        io_tcp_server_conn_signal_error(conn, "cannot shutdown socket: %s",
                                        strerror(errno));

        io_tcp_server_conn_close_discard(conn);
        return;
    }

    if (io_tcp_server_conn_watch(conn, IO_EVENT_FD_WRITE) == -1) {
        io_tcp_server_conn_signal_error(conn, "%s", c_get_error());
        io_tcp_server_conn_close_discard(conn);
        return;
    }

    conn->state = IO_TCP_SERVER_CONN_STATE_DISCONNECTING;
}

void
io_tcp_server_conn_close(struct io_tcp_server_conn *conn) {
    if (conn->state == IO_TCP_SERVER_CONN_STATE_DISCONNECTED)
        return;

    if (io_base_is_fd_watched(conn->server->base, conn->sock)) {
        if (io_base_unwatch_fd(conn->server->base, conn->sock) == -1) {
            io_tcp_server_conn_signal_error(conn, "cannot unwatch socket: %s",
                                  c_get_error());
        }
    }

    close(conn->sock);
    conn->sock = -1;

    if (conn->uses_ssl) {
        io_ssl_delete(conn->ssl);
        conn->ssl = NULL;
        conn->ssl_last_write_sz = 0;
    }

    conn->state = IO_TCP_SERVER_CONN_STATE_DISCONNECTED;
}

void
io_tcp_server_conn_write(struct io_tcp_server_conn *conn,
                         const void *data, size_t sz) {
    if (conn->state != IO_TCP_SERVER_CONN_STATE_CONNECTED)
        return;

    if (sz == 0)
        return;

    c_buffer_add(conn->wbuf, data, sz);

    io_tcp_server_conn_signal_data_written(conn);
}

void
io_tcp_server_conn_signal_data_written(struct io_tcp_server_conn *conn) {
    uint32_t flags;

    if (conn->state != IO_TCP_SERVER_CONN_STATE_CONNECTED)
        return;

    flags = IO_EVENT_FD_READ | IO_EVENT_FD_WRITE;

    if (io_tcp_server_conn_watch(conn, flags) == -1) {
        io_tcp_server_conn_signal_error(conn, "%s", c_get_error());

        conn->failing = true;
    }
}

const struct io_address *
io_tcp_server_conn_address(const struct io_tcp_server_conn *conn) {
    return &conn->addr;
}

struct c_buffer *
io_tcp_server_conn_rbuf(const struct io_tcp_server_conn *conn) {
    return conn->rbuf;
}

struct c_buffer *
io_tcp_server_conn_wbuf(const struct io_tcp_server_conn *conn) {
    return conn->wbuf;
}

void
io_tcp_server_conn_set_private_data(struct io_tcp_server_conn *conn,
                                    void *data) {
    conn->private_data = data;
}

void *
io_tcp_server_conn_private_data(const struct io_tcp_server_conn *conn) {
    return conn->private_data;
}

static int
io_tcp_server_conn_watch(struct io_tcp_server_conn *conn, uint32_t events) {
    if (io_base_watch_fd(conn->server->base, conn->sock, events,
                         io_tcp_server_conn_on_event, conn) == -1) {
        c_set_error("cannot watch socket: %s", c_get_error());
        return -1;
    }

    return 0;
}

static void
io_tcp_server_conn_signal_event(struct io_tcp_server_conn *conn,
                                enum io_tcp_server_event event) {
    struct io_tcp_server *server;

    server = conn->server;

    if (!server->event_cb)
        return;

    server->event_cb(server, conn, event, server->event_cb_arg);
}

static void
io_tcp_server_conn_signal_error(struct io_tcp_server_conn *conn,
                                const char *fmt, ...) {
    char buf[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    c_set_error("%s", buf);
    io_tcp_server_conn_signal_event(conn, IO_TCP_SERVER_EVENT_ERROR);
}

static void
io_tcp_server_conn_on_event_ssl_accepting(int sock, uint32_t events,
                                          void *arg) {
    struct io_tcp_server_conn *conn;

    conn = arg;

    assert(conn->state == IO_TCP_SERVER_CONN_STATE_SSL_ACCEPTING);

    if (io_tcp_server_conn_ssl_accept(conn) == -1) {
        io_tcp_server_conn_signal_error(conn, "%s", c_get_error());
        io_tcp_server_conn_close_discard(conn);
        return;
    }

    if (conn->state == IO_TCP_SERVER_CONN_STATE_CONNECTED)
        io_tcp_server_conn_on_connected(conn);
}

static void
io_tcp_server_conn_on_event(int sock, uint32_t events, void *arg) {
    struct io_tcp_server_conn *conn;

    conn = arg;

    assert(conn->state == IO_TCP_SERVER_CONN_STATE_CONNECTED
        || conn->state == IO_TCP_SERVER_CONN_STATE_DISCONNECTING);

    if (events & IO_EVENT_FD_READ) {
        ssize_t ret;

        if (conn->uses_ssl) {
            int err;

            ret = io_ssl_read(conn->ssl, conn->rbuf, BUFSIZ, &err);

            if (ret == -1) {
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    return;
            }
        } else {
            ret = c_buffer_read(conn->rbuf, conn->sock, BUFSIZ);
        }

        if (ret == -1) {
            io_tcp_server_conn_signal_error(conn, "cannot read socket: %s",
                                            c_get_error());
            io_tcp_server_conn_close_discard(conn);
            return;
        } else if (ret == 0) {
            io_tcp_server_conn_close_discard(conn);
            return;
        }

        io_tcp_server_conn_signal_event(conn, IO_TCP_SERVER_EVENT_DATA_READ);
        if (conn->state == IO_TCP_SERVER_CONN_STATE_DISCONNECTED) {
            io_tcp_server_conn_discard(conn);
            return;
        } else if (conn->failing) {
            io_tcp_server_conn_close_discard(conn);
            return;
        }
    }

    if (events & IO_EVENT_FD_WRITE) {
        ssize_t ret;

        if (conn->uses_ssl) {
            ret = io_ssl_write(conn->ssl, conn->wbuf, &conn->ssl_last_write_sz);
        } else {
            ret = c_buffer_write(conn->wbuf, conn->sock);
        }

        if (ret == -1) {
            io_tcp_server_conn_signal_error(conn, "cannot write socket: %s",
                                            strerror(errno));
            io_tcp_server_conn_close_discard(conn);
            return;
        }

        if (c_buffer_length(conn->wbuf) == 0) {
            if (conn->state == IO_TCP_SERVER_CONN_STATE_DISCONNECTING) {
                io_tcp_server_conn_close_discard(conn);
                return;
            }

            if (io_tcp_server_conn_watch(conn, IO_EVENT_FD_READ) == -1) {
                io_tcp_server_conn_signal_error(conn, "%s", c_get_error());
                io_tcp_server_conn_close_discard(conn);
                return;
            }
        }
    }
}

/* ------------------------------------------------------------------------
 *  Listener
 * ------------------------------------------------------------------------ */
const struct io_address *
io_tcp_listener_address(const struct io_tcp_listener *listener) {
    return &listener->address;
}

/* ------------------------------------------------------------------------
 *  Server
 * ------------------------------------------------------------------------ */
static void io_tcp_server_signal_event(struct io_tcp_server *,
                                       enum io_tcp_server_event);
static void io_tcp_server_signal_error(struct io_tcp_server *,
                                       const char *, ...)
    __attribute__((format(printf, 2, 3)));

static void io_tcp_server_on_event(int, uint32_t, void *);

struct io_tcp_server *
io_tcp_server_new(struct io_base *base, io_tcp_server_event_cb cb,
                  void *cb_arg) {
    struct io_tcp_server *server;

    server = c_malloc0(sizeof(struct io_tcp_server));

    server->state = IO_TCP_SERVER_STATE_STOPPED;

    server->connections = c_queue_new();

    server->event_cb = cb;
    server->event_cb_arg = cb_arg;

    server->base = base;

    return server;
}

void
io_tcp_server_delete(struct io_tcp_server *server) {
    if (!server)
        return;

    c_free(server->host);

    c_vector_delete(server->listeners);

    c_queue_delete(server->connections);

    c_free0(server, sizeof(struct io_tcp_server));
}

const char *
io_tcp_server_host(const struct io_tcp_server *server) {
    return server->host;
}

uint16_t
io_tcp_server_port(const struct io_tcp_server *server) {
    return server->port;
}

size_t
io_tcp_server_nb_listeners(const struct io_tcp_server *server) {
    return c_vector_length(server->listeners);
}

const struct io_tcp_listener *
io_tcp_server_nth_listener(const struct io_tcp_server *server, size_t idx) {
    return c_vector_entry(server->listeners, idx);
}

int
io_tcp_server_enable_ssl(struct io_tcp_server *server,
                         const struct io_ssl_cfg *cfg) {
    SSL_CTX *ctx;

    assert(!server->uses_ssl);

    ctx = io_ssl_ctx_new_server(cfg);
    if (!ctx)
        return -1;

    server->uses_ssl = true;
    server->ssl_ctx = ctx;
    return 0;
}

bool
io_tcp_server_is_ssl_enabled(struct io_tcp_server *server) {
    return server->uses_ssl;
}

int
io_tcp_server_listen(struct io_tcp_server *server,
                     const char *host, uint16_t port) {
    struct c_vector *listeners;
    struct io_address *addrs;
    size_t nb_addrs;

    assert(server->state == IO_TCP_SERVER_STATE_STOPPED);

    if (io_address_resolve(host, port, AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP,
                           &addrs, &nb_addrs) == -1) {
        c_set_error("cannot resolve address: %s", c_get_error());
        return -1;
    }

    listeners = c_vector_new(sizeof(struct io_tcp_listener));

    for (size_t i = 0; i < nb_addrs; i++) {
        struct io_tcp_listener listener;
        struct io_address *addr;
        int sock, opt;

        addr = addrs + i;

        sock = socket(io_address_family(addr), SOCK_STREAM, IPPROTO_TCP);
        if (sock == -1) {
            c_set_error("cannot create socket: %s", strerror(errno));
            goto error;
        }

        opt = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                       &opt, sizeof(int)) == -1) {
            c_set_error("cannot set SO_REUSEADDR: %s", strerror(errno));
            close(sock);
            goto error;
        }

        if (bind(sock, io_address_sockaddr(addr),
                 io_address_length(addr)) == -1) {
            c_set_error("cannot bind socket: %s", strerror(errno));
            close(sock);
            goto error;
        }

        if (listen(sock, 10) == -1) {
            c_set_error("cannot listen on socket: %s", strerror(errno));
            close(sock);
            goto error;
        }

        if (io_base_watch_fd(server->base, sock, IO_EVENT_FD_READ,
                             io_tcp_server_on_event, server) == -1) {
            c_set_error("cannot watch socket: %s", c_get_error());
            close(sock);
            goto error;
        }

        listener.address = *addr;
        listener.sock = sock;

        c_vector_append(listeners, &listener);
    }

    server->host = c_strdup(host);
    server->port = port;

    server->listeners = listeners;

    server->state = IO_TCP_SERVER_STATE_LISTENING;

    io_tcp_server_signal_event(server, IO_TCP_SERVER_EVENT_SERVER_LISTENING);

    c_free(addrs);
    return 0;

error:
    c_vector_delete(listeners);
    c_free(addrs);
    return -1;
}

void
io_tcp_server_stop(struct io_tcp_server *server) {
    struct c_queue_entry *entry;

    assert(server->state == IO_TCP_SERVER_STATE_LISTENING);

    for (size_t i = 0; i < c_vector_length(server->listeners); i++) {
        struct io_tcp_listener *listener;

        listener = c_vector_entry(server->listeners, i);

        if (io_base_unwatch_fd(server->base, listener->sock) == -1) {
            io_tcp_server_signal_error(server, "cannot unwatch socket: %s",
                                       c_get_error());
        }
    }

    /* The proper way would be disconnect all connections and wait for the
     * last one to be closed, then close the server. Infortunately, it means
     * checking whether the connection list is empty or not each time a
     * conn is removed. I have to do it one day... */

    entry = c_queue_first_entry(server->connections);
    while (entry) {
        struct io_tcp_server_conn *conn;

        conn = c_queue_entry_value(entry);

        io_tcp_server_conn_close(conn);
        io_tcp_server_conn_signal_event(conn, IO_TCP_SERVER_EVENT_CONN_CLOSED);
        io_tcp_server_conn_delete(conn);

        entry = c_queue_entry_next(entry);
    }

    c_queue_clear(server->connections);

    io_tcp_server_close(server);
    io_tcp_server_signal_event(server, IO_TCP_SERVER_EVENT_SERVER_STOPPED);
}

void
io_tcp_server_close(struct io_tcp_server *server) {
    struct c_queue_entry *entry;

    if (server->state == IO_TCP_SERVER_STATE_STOPPED)
        return;

    for (size_t i = 0; i < c_vector_length(server->listeners); i++) {
        struct io_tcp_listener *listener;

        listener = c_vector_entry(server->listeners, i);

        close(listener->sock);
        listener->sock = -1;
    }

    entry = c_queue_first_entry(server->connections);
    while (entry) {
        struct io_tcp_server_conn *conn;

        conn = c_queue_entry_value(entry);

        io_tcp_server_conn_close(conn);
        io_tcp_server_conn_delete(conn);

        entry = c_queue_entry_next(entry);
    }

    c_queue_clear(server->connections);

    if (server->uses_ssl) {
        io_ssl_ctx_delete(server->ssl_ctx);
        server->ssl_ctx = NULL;
    }

    server->state = IO_TCP_SERVER_STATE_STOPPED;
}

void
io_tcp_server_add_conn(struct io_tcp_server *server,
                       struct io_tcp_server_conn *conn) {
    assert(!conn->queue_entry);

    c_queue_push(server->connections, conn);
    conn->queue_entry = c_queue_last_entry(server->connections);
}

void
io_tcp_server_remove_conn(struct io_tcp_server *server,
                          struct io_tcp_server_conn *conn) {
    assert(conn->queue_entry);

    c_queue_remove_entry(server->connections, conn->queue_entry);
    c_queue_entry_delete(conn->queue_entry);
    conn->queue_entry = NULL;
}

static void
io_tcp_server_signal_event(struct io_tcp_server *server,
                           enum io_tcp_server_event event) {
    if (!server->event_cb)
        return;

    server->event_cb(server, NULL, event, server->event_cb_arg);
}

static void
io_tcp_server_signal_error(struct io_tcp_server *server, const char *fmt, ...) {
    char buf[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    c_set_error("%s", buf);
    io_tcp_server_signal_event(server, IO_TCP_SERVER_EVENT_ERROR);
}

static void
io_tcp_server_conn_on_connected(struct io_tcp_server_conn *conn) {
    if (io_tcp_server_conn_watch(conn, IO_EVENT_FD_READ) == -1) {
        io_tcp_server_conn_signal_error(conn, "%s", c_get_error());
        io_tcp_server_conn_close_discard(conn);
        return;
    }

    io_tcp_server_conn_signal_event(conn, IO_TCP_SERVER_EVENT_CONN_ACCEPTED);
    if (conn->state == IO_TCP_SERVER_CONN_STATE_DISCONNECTED) {
        io_tcp_server_conn_discard(conn);
        return;
    } else if (conn->failing) {
        io_tcp_server_conn_close_discard(conn);
        return;
    }
}

static void
io_tcp_server_on_event(int sock, uint32_t events, void *arg) {
    struct io_tcp_server *server;
    struct io_tcp_server_conn *conn;
    struct sockaddr_storage ss;
    socklen_t ss_len;
    struct io_address addr;
    int csock;

    server = arg;

    assert(server->state == IO_TCP_SERVER_STATE_LISTENING);
    assert(events & IO_EVENT_FD_READ);

    ss_len = sizeof(struct sockaddr_storage);
    csock = accept(sock, (struct sockaddr *)&ss, &ss_len);
    if (csock == -1) {
        io_tcp_server_signal_error(server, "cannot accept connection: %s",
                                   c_get_error());
        return;
    }

    if (io_address_init_from_sockaddr_storage(&addr, &ss) == -1) {
        io_tcp_server_signal_error(server,
                                   "cannot initialize connection address: %s",
                                   c_get_error());
        close(csock);
        return;
    }

    conn = io_tcp_server_conn_new(server, csock);
    conn->addr = addr;

    io_tcp_server_add_conn(server, conn);

    if (server->uses_ssl) {
        conn->uses_ssl = true;

        conn->state = IO_TCP_SERVER_CONN_STATE_SSL_ACCEPTING;

        conn->ssl = io_ssl_new(server->ssl_ctx, conn->sock);
        if (!conn->ssl) {
            io_tcp_server_conn_signal_error(conn, "%s", c_get_error());
            io_tcp_server_conn_close_discard(conn);
            return;
        }

        if (io_tcp_server_conn_ssl_accept(conn) == -1) {
            io_tcp_server_conn_signal_error(conn, "%s", c_get_error());
            io_tcp_server_conn_close_discard(conn);
            return;
        }

        if (conn->state == IO_TCP_SERVER_CONN_STATE_CONNECTED)
            io_tcp_server_conn_on_connected(conn);
    } else {
        conn->state = IO_TCP_SERVER_CONN_STATE_CONNECTED;
        io_tcp_server_conn_on_connected(conn);
    }
}
