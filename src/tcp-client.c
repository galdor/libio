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

static int io_tcp_client_try_connect(struct io_tcp_client *);

static int io_tcp_client_watch(struct io_tcp_client *, uint32_t);
static void io_tcp_client_signal_event(struct io_tcp_client *,
                                       enum io_tcp_client_event);
static void io_tcp_client_signal_error(struct io_tcp_client *,
                                       const char *, ...)
    __attribute__((format(printf, 2, 3)));

static void io_tcp_client_on_conn_established(struct io_tcp_client *);

static void io_tcp_client_on_event_connecting(int, uint32_t, void *);
static void io_tcp_client_on_event_ssl_connecting(int, uint32_t, void *);
static void io_tcp_client_on_event(int, uint32_t, void *);

struct io_tcp_client *
io_tcp_client_new(struct io_base *base,
                  io_tcp_client_event_cb cb, void *cb_arg) {
    struct io_tcp_client *client;

    client = c_malloc0(sizeof(struct io_tcp_client));

    client->state = IO_TCP_CLIENT_STATE_DISCONNECTED;

    client->sock = -1;

    client->rbuf = c_buffer_new();
    client->wbuf = c_buffer_new();

    client->event_cb = cb;
    client->event_cb_arg = cb_arg;

    client->base = base;

    return client;
}

void
io_tcp_client_delete(struct io_tcp_client *client) {
    if (!client)
        return;

    c_free(client->host);
    c_free(client->addrs);

    c_buffer_delete(client->rbuf);
    c_buffer_delete(client->wbuf);

    c_free0(client, sizeof(struct io_tcp_client));
}

const char *
io_tcp_client_host(const struct io_tcp_client *client) {
    return client->host;
}

uint16_t
io_tcp_client_port(const struct io_tcp_client *client) {
    return client->port;
}

int
io_tcp_client_enable_ssl(struct io_tcp_client *client,
                         const struct io_ssl_client_cfg *cfg) {
    SSL_CTX *ctx;

    assert(!client->uses_ssl);

    ctx = io_ssl_ctx_new_client(cfg);
    if (!ctx)
        return -1;

    client->uses_ssl = true;
    client->ssl_ctx = ctx;
    return 0;
}

bool
io_tcp_client_is_ssl_enabled(struct io_tcp_client *client) {
    return client->uses_ssl;
}

bool
io_tcp_client_is_connected(const struct io_tcp_client *client) {
    return client->state == IO_TCP_CLIENT_STATE_CONNECTED;
}

struct c_buffer *
io_tcp_client_rbuf(const struct io_tcp_client *client) {
    return client->rbuf;
}

struct c_buffer *
io_tcp_client_wbuf(const struct io_tcp_client *client) {
    return client->wbuf;
}

int
io_tcp_client_connect(struct io_tcp_client *client,
                      const char *host, uint16_t port) {
    struct io_address *addrs;
    size_t nb_addrs;

    assert(client->state == IO_TCP_CLIENT_STATE_DISCONNECTED);

    if (io_address_resolve(host, port, AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP,
                           &addrs, &nb_addrs) == -1) {
        c_set_error("cannot resolve address: %s", c_get_error());
        return -1;
    }

    c_free(client->host);
    client->host = c_strdup(host);
    client->port = port;

    client->addrs = addrs;
    client->nb_addrs = nb_addrs;
    client->addr_idx = 0;

    return io_tcp_client_try_connect(client);
}

void
io_tcp_client_disconnect(struct io_tcp_client *client) {
    int mode;

    if (client->state == IO_TCP_CLIENT_STATE_DISCONNECTING
     || client->state == IO_TCP_CLIENT_STATE_DISCONNECTED) {
        return;
    }

    if (c_buffer_length(client->wbuf) == 0) {
        mode = SHUT_RDWR;
    } else {
        mode = SHUT_RD;
    }

    if (shutdown(client->sock, mode) == -1) {
        if (errno == ENOTCONN) {
            /* The connection is already closed; we clear the write buffer to
             * make sure we will not try to write anything. */
            c_buffer_clear(client->wbuf);
        } else {
            io_tcp_client_signal_error(client, "cannot shutdown socket: %s",
                                       strerror(errno));
            client->failing = true;
            return;
        }
    }

    if (io_tcp_client_watch(client, IO_EVENT_FD_WRITE) == -1) {
        io_tcp_client_signal_error(client, "%s", c_get_error());
        client->failing = true;
        return;
    }

    client->state = IO_TCP_CLIENT_STATE_DISCONNECTING;
}

int
io_tcp_client_reconnect(struct io_tcp_client *client) {
    assert(client->state == IO_TCP_CLIENT_STATE_DISCONNECTED);

    client->addr_idx = 0;

    c_buffer_clear(client->rbuf);

    return io_tcp_client_try_connect(client);
}

void
io_tcp_client_close(struct io_tcp_client *client) {
    if (client->uses_ssl) {
        io_ssl_ctx_delete(client->ssl_ctx);
        client->ssl_ctx = NULL;
    }

    if (client->state == IO_TCP_CLIENT_STATE_DISCONNECTED)
        return;

    if (io_base_is_fd_watched(client->base, client->sock)) {
        if (io_base_unwatch_fd(client->base, client->sock) == -1) {
            io_tcp_client_signal_error(client, "cannot unwatch socket: %s",
                                 c_get_error());
        }
    }

    close(client->sock);
    client->sock = -1;

    c_buffer_clear(client->wbuf);

    if (client->uses_ssl) {
        io_ssl_delete(client->ssl);
        client->ssl = NULL;

        client->ssl_last_write_sz = 0;
    }

    client->state = IO_TCP_CLIENT_STATE_DISCONNECTED;
}

void
io_tcp_client_write(struct io_tcp_client *client, const void *data, size_t sz) {
    if (client->state != IO_TCP_CLIENT_STATE_CONNECTED) {
        io_tcp_client_signal_error(client,
                                   "cannot write: client is not connected");
        return;
    }

    if (client->failing)
        return;

    if (sz == 0)
        return;

    c_buffer_add(client->wbuf, data, sz);

    io_tcp_client_signal_data_written(client);
}

void
io_tcp_client_signal_data_written(struct io_tcp_client *client) {
    uint32_t flags;

    if (client->state != IO_TCP_CLIENT_STATE_CONNECTED) {
        io_tcp_client_signal_error(client,
                                   "cannot write: client is not connected");
        return;
    }

    if (client->failing)
        return;

    flags = IO_EVENT_FD_READ | IO_EVENT_FD_WRITE;

    if (io_tcp_client_watch(client, flags) == -1) {
        io_tcp_client_signal_error(client, "%s", c_get_error());

        client->failing = true;
    }
}

int
io_tcp_client_ssl_connect(struct io_tcp_client *client) {
    int ret;

    assert(client->state == IO_TCP_CLIENT_STATE_SSL_CONNECTING);
    assert(client->uses_ssl);

    ret = SSL_connect(client->ssl);
    if (ret != 1) {
        int err;

        err = SSL_get_error(client->ssl, ret);

        switch (err) {
        case SSL_ERROR_WANT_READ:
            if (io_base_watch_fd(client->base, client->sock, IO_EVENT_FD_READ,
                                 io_tcp_client_on_event_ssl_connecting,
                                 client) == -1) {
                c_set_error("cannot watch socket: %s", c_get_error());
                return -1;
            }
            break;

        case SSL_ERROR_WANT_WRITE:
            if (io_base_watch_fd(client->base, client->sock, IO_EVENT_FD_WRITE,
                                 io_tcp_client_on_event_ssl_connecting,
                                 client) == -1) {
                c_set_error("cannot watch socket: %s", c_get_error());
                return -1;
            }
            break;

        default:
            c_set_error("cannot establish ssl connection: %s",
                        io_ssl_get_error());
            return -1;
        }

        return 0;
    }

    client->state = IO_TCP_CLIENT_STATE_CONNECTED;
    return 0;
}

static int
io_tcp_client_try_connect(struct io_tcp_client *client) {
    struct io_address *addr;
    int sock;

    assert(client->state == IO_TCP_CLIENT_STATE_DISCONNECTED);

    addr = client->addrs + client->addr_idx;

    sock = socket(io_address_family(addr), SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        c_set_error("cannot create socket: %s", strerror(errno));
        return -1;
    }

    if (io_fd_set_non_blocking(sock) == -1) {
        close(sock);
        return -1;
    }

    if (connect(sock, io_address_sockaddr(addr),
                io_address_length(addr)) == -1) {
        if (errno != EINPROGRESS) {
            c_set_error("cannot connect socket: %s", strerror(errno));
            close(sock);
            return -1;
        }
    }

    if (io_base_watch_fd(client->base, sock, IO_EVENT_FD_WRITE,
                         io_tcp_client_on_event_connecting, client) == -1) {
        c_set_error("cannot watch socket: %s", c_get_error());
        close(sock);
        return -1;
    }

    client->sock = sock;
    client->state = IO_TCP_CLIENT_STATE_CONNECTING;

    return 0;
}

static int
io_tcp_client_watch(struct io_tcp_client *client, uint32_t events) {
    if (io_base_watch_fd(client->base, client->sock, events,
                         io_tcp_client_on_event, client) == -1) {
        c_set_error("cannot watch socket: %s", c_get_error());
        return -1;
    }

    return 0;
}

static void
io_tcp_client_signal_event(struct io_tcp_client *client,
                           enum io_tcp_client_event event) {
    if (!client->event_cb)
        return;

    client->event_cb(client, event, client->event_cb_arg);
}

static void
io_tcp_client_signal_error(struct io_tcp_client *client, const char *fmt, ...) {
    char buf[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    c_set_error("%s", buf);
    io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_ERROR);
}

static void
io_tcp_client_on_conn_established(struct io_tcp_client *client) {
    uint32_t wevents;

    assert(client->state == IO_TCP_CLIENT_STATE_CONNECTED);

    io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_CONN_ESTABLISHED);
    if (client->failing) {
        io_tcp_client_close(client);
        io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_CONN_CLOSED);
    }
    if (client->state == IO_TCP_CLIENT_EVENT_CONN_CLOSED)
        return;

    /* Watch the socket. Note that the event handler may have written data; in
     * that case, we must watch for write events. */
    wevents = IO_EVENT_FD_READ;
    if (c_buffer_length(client->wbuf) > 0)
        wevents |= IO_EVENT_FD_WRITE;

    if (io_tcp_client_watch(client, wevents) == -1) {
        io_tcp_client_signal_error(client, "%s", c_get_error());

        io_tcp_client_close(client);
        io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_CONN_CLOSED);
        return;
    }
}

static void
io_tcp_client_on_event_connecting(int sock, uint32_t events, void *arg) {
    struct io_tcp_client *client;
    socklen_t len;
    int error;

    client = arg;

    assert(client->state == IO_TCP_CLIENT_STATE_CONNECTING);

    /* Check the socket status to know whether the connection succeeded or
     * not */
    error = 0;
    len = sizeof(int);
    if (getsockopt(client->sock, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
        io_tcp_client_signal_error(client, "cannot get socket error: %s",
                             strerror(errno));

        io_tcp_client_close(client);
        io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_CONN_FAILED);
        return;
    }

    if (error != 0) {
        const struct io_address *addr;

        addr = client->addrs + client->addr_idx;

        io_tcp_client_signal_error(client, "cannot connect socket to %s: %s",
                                   io_address_host_port_string(addr),
                                   strerror(error));

        io_tcp_client_close(client);

        if (client->addr_idx == client->nb_addrs - 1) {
            /* No more address to try */
            io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_CONN_FAILED);
            return;
        }

        client->addr_idx++;

        if (io_tcp_client_try_connect(client) == -1) {
            io_tcp_client_signal_error(client, "%s", c_get_error());
            io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_CONN_CLOSED);
            return;
        }

        return;
    }

    /* The connection is now established */
    if (client->uses_ssl) {
        client->state = IO_TCP_CLIENT_STATE_SSL_CONNECTING;

        client->ssl = io_ssl_new(client->ssl_ctx, client->sock);
        if (!client->ssl) {
            io_tcp_client_signal_error(client, "%s", c_get_error());

            io_tcp_client_close(client);
            io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_CONN_CLOSED);
            return;
        }

        if (io_tcp_client_ssl_connect(client) == -1) {
            io_tcp_client_signal_error(client, "%s", c_get_error());

            io_tcp_client_close(client);
            io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_CONN_CLOSED);
            return;
        }

        if (client->state == IO_TCP_CLIENT_STATE_CONNECTED)
            io_tcp_client_on_conn_established(client);
    } else {
        client->state = IO_TCP_CLIENT_STATE_CONNECTED;
        io_tcp_client_on_conn_established(client);
    }
}

static void
io_tcp_client_on_event_ssl_connecting(int sock, uint32_t events, void *arg) {
    struct io_tcp_client *client;

    client = arg;

    assert(client->state == IO_TCP_CLIENT_STATE_SSL_CONNECTING);
    assert(client->uses_ssl);

    if (io_tcp_client_ssl_connect(client) == -1) {
        io_tcp_client_signal_error(client, "%s", c_get_error());

        io_tcp_client_close(client);
        io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_CONN_CLOSED);
        return;
    }

    if (client->state == IO_TCP_CLIENT_STATE_CONNECTED)
        io_tcp_client_on_conn_established(client);
}

static void
io_tcp_client_on_event(int sock, uint32_t events, void *arg) {
    struct io_tcp_client *client;

    client = arg;

    assert(client->state == IO_TCP_CLIENT_STATE_CONNECTED
        || client->state == IO_TCP_CLIENT_STATE_DISCONNECTING);

    if (events & IO_EVENT_FD_READ) {
        ssize_t ret;

        if (client->uses_ssl) {
            int err;

            ret = io_ssl_read(client->ssl, client->rbuf, BUFSIZ, &err);

            if (ret == -1) {
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                    return;
            }
        } else {
            ret = c_buffer_read(client->rbuf, client->sock, BUFSIZ);
        }

        if (ret == -1) {
            io_tcp_client_signal_error(client, "cannot read socket: %s",
                                       c_get_error());

            io_tcp_client_close(client);
            io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_CONN_CLOSED);
            return;
        } else if (ret == 0) {
            io_tcp_client_close(client);
            io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_CONN_CLOSED);
            return;
        }

        io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_DATA_READ);
        if (client->failing) {
            io_tcp_client_close(client);
            io_tcp_client_signal_event(client, IO_TCP_CLIENT_EVENT_CONN_CLOSED);
        }
        if (client->state == IO_TCP_CLIENT_EVENT_CONN_CLOSED)
            return;
    }

    if (events & IO_EVENT_FD_WRITE) {
        ssize_t ret;

        if (c_buffer_length(client->wbuf) > 0) {
            if (client->uses_ssl) {
                ret = io_ssl_write(client->ssl, client->wbuf,
                                   &client->ssl_last_write_sz);
            } else {
                ret = c_buffer_write(client->wbuf, client->sock);
            }

            if (ret == -1) {
                io_tcp_client_signal_error(client, "cannot write socket: %s",
                                           strerror(errno));

                io_tcp_client_close(client);
                io_tcp_client_signal_event(client,
                                           IO_TCP_CLIENT_EVENT_CONN_CLOSED);
                return;
            }
        }

        if (c_buffer_length(client->wbuf) == 0) {
            if (client->state == IO_TCP_CLIENT_STATE_DISCONNECTING) {
                io_tcp_client_close(client);
                io_tcp_client_signal_event(client,
                                           IO_TCP_CLIENT_EVENT_CONN_CLOSED);
                return;
            }

            if (io_tcp_client_watch(client, IO_EVENT_FD_READ) == -1) {
                io_tcp_client_signal_error(client, "%s", c_get_error());

                io_tcp_client_close(client);
                io_tcp_client_signal_event(client,
                                           IO_TCP_CLIENT_EVENT_CONN_CLOSED);
                return;
            }
        }
    }
}
