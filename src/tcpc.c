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

static int io_tcpc_watch(struct io_tcpc *, uint32_t);
static void io_tcpc_signal_event(struct io_tcpc *, enum io_tcpc_event);
static void io_tcpc_signal_error(struct io_tcpc *, const char *, ...)
    __attribute__((format(printf, 2, 3)));

static void io_tcpc_on_event_connecting(int, uint32_t, void *);
static void io_tcpc_on_event(int, uint32_t, void *);

struct io_tcpc *
io_tcpc_new(struct io_base *base, io_tcpc_event_cb cb, void *cb_arg) {
    struct io_tcpc *client;

    client = c_malloc0(sizeof(struct io_tcpc));

    client->state = IO_TCPC_STATE_DISCONNECTED;

    client->sock = -1;

    client->rbuf = c_buffer_new();
    client->wbuf = c_buffer_new();

    client->event_cb = cb;
    client->event_cb_arg = cb_arg;

    client->base = base;

    return client;
}

void
io_tcpc_delete(struct io_tcpc *client) {
    if (!client)
        return;

    c_free(client->host);

    c_buffer_delete(client->rbuf);
    c_buffer_delete(client->wbuf);

    c_free0(client, sizeof(struct io_tcpc));
}

struct c_buffer *
io_tcpc_rbuf(const struct io_tcpc *client) {
    return client->rbuf;
}

int
io_tcpc_connect(struct io_tcpc *client, const char *host, uint16_t port) {
    struct io_address addr;
    int sock;

    assert(client->state == IO_TCPC_STATE_DISCONNECTED);

    if (io_address_init(&addr, host, port) == -1) {
        c_set_error("cannot initialize address: %s", c_get_error());
        return -1;
    }

    sock = socket(io_address_family(&addr), SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        c_set_error("cannot create socket: %s", strerror(errno));
        return -1;
    }

    if (io_fd_set_non_blocking(sock) == -1) {
        close(sock);
        return -1;
    }

    if (connect(sock, io_address_sockaddr(&addr),
                io_address_length(&addr)) == -1) {
        if (errno != EINPROGRESS) {
            c_set_error("cannot connect socket: %s", strerror(errno));
            close(sock);
            return -1;
        }
    }

    if (io_base_watch_fd(client->base, sock, IO_EVENT_FD_WRITE,
                         io_tcpc_on_event_connecting, client) == -1) {
        c_set_error("cannot watch socket: %s", c_get_error());
        close(sock);
        return -1;
    }

    c_free(client->host);
    client->host = c_strdup(host);
    client->port = port;
    client->addr = addr;

    client->sock = sock;

    client->state = IO_TCPC_STATE_CONNECTING;
    return 0;
}

void
io_tcpc_disconnect(struct io_tcpc *client) {
    assert(client->state == IO_TCPC_STATE_CONNECTED);

    if (c_buffer_length(client->wbuf) == 0) {
        io_tcpc_close(client);
        io_tcpc_signal_event(client, IO_TCPC_EVENT_CONNECTION_CLOSED);
        return;
    }

    if (shutdown(client->sock, SHUT_RD) == -1) {
        io_tcpc_signal_error(client, "cannot shutdown socket: %s",
                             strerror(errno));

        io_tcpc_close(client);
        io_tcpc_signal_event(client, IO_TCPC_EVENT_CONNECTION_CLOSED);
        return;
    }

    if (io_tcpc_watch(client, IO_EVENT_FD_WRITE) == -1) {
        io_tcpc_signal_error(client, "%s", c_get_error());

        io_tcpc_close(client);
        io_tcpc_signal_event(client, IO_TCPC_EVENT_CONNECTION_CLOSED);
        return;
    }

    client->state = IO_TCPC_STATE_DISCONNECTING;
}

void
io_tcpc_close(struct io_tcpc *client) {
    if (client->state == IO_TCPC_STATE_DISCONNECTED)
        return;

    if (io_base_unwatch_fd(client->base, client->sock) == -1) {
        io_tcpc_signal_error(client, "cannot unwatch socket: %s",
                             c_get_error());
    }

    close(client->sock);
    client->sock = -1;

    c_buffer_clear(client->rbuf);
    c_buffer_clear(client->wbuf);

    client->state = IO_TCPC_STATE_DISCONNECTED;
}

int
io_tcpc_write(struct io_tcpc *client, const void *data, size_t sz) {
    assert(client->state == IO_TCPC_STATE_CONNECTED);

    if (sz == 0)
        return 0;

    c_buffer_add(client->wbuf, data, sz);

    return io_tcpc_watch(client, IO_EVENT_FD_READ | IO_EVENT_FD_WRITE);
}

static int
io_tcpc_watch(struct io_tcpc *client, uint32_t events) {
    if (io_base_watch_fd(client->base, client->sock, events,
                         io_tcpc_on_event, client) == -1) {
        c_set_error("cannot watch socket: %s", c_get_error());
        return -1;
    }

    return 0;
}

static void
io_tcpc_signal_event(struct io_tcpc *client, enum io_tcpc_event event) {
    if (!client->event_cb)
        return;

    client->event_cb(client, event, client->event_cb_arg);
}

static void
io_tcpc_signal_error(struct io_tcpc *client, const char *fmt, ...) {
    char buf[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    c_set_error("%s", buf);
    io_tcpc_signal_event(client, IO_TCPC_EVENT_ERROR);
}

static void
io_tcpc_on_event_connecting(int sock, uint32_t events, void *arg) {
    struct io_tcpc *client;
    uint32_t wevents;
    socklen_t len;
    int error;

    client = arg;

    assert(client->state == IO_TCPC_STATE_CONNECTING);

    /* Check the socket status to know whether the connection succeeded or
     * not */
    len = sizeof(int);
    if (getsockopt(client->sock, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
        io_tcpc_signal_error(client, "cannot get socket error: %s",
                             strerror(errno));

        io_tcpc_close(client);
        io_tcpc_signal_event(client, IO_TCPC_EVENT_CONNECTION_FAILED);
        return;
    }

    if (error != 0) {
        io_tcpc_signal_error(client, "cannot connect socket to %s: %s",
                             io_address_host_port_string(&client->addr),
                             strerror(error));

        io_tcpc_close(client);
        io_tcpc_signal_event(client, IO_TCPC_EVENT_CONNECTION_FAILED);
        return;
    }

    /* The connection is now established */
    client->state = IO_TCPC_STATE_CONNECTED;
    io_tcpc_signal_event(client, IO_TCPC_EVENT_CONNECTION_ESTABLISHED);

    /* Watch the socket. Note that the event handler may have written data; in
     * that case, we must watch for write events. */
    wevents = IO_EVENT_FD_READ;
    if (c_buffer_length(client->wbuf) > 0)
        wevents |= IO_EVENT_FD_WRITE;

    if (io_tcpc_watch(client, wevents) == -1) {
        io_tcpc_signal_error(client, "%s", c_get_error());

        io_tcpc_close(client);
        io_tcpc_signal_event(client, IO_TCPC_EVENT_CONNECTION_CLOSED);
        return;
    }
}

static void
io_tcpc_on_event(int sock, uint32_t events, void *arg) {
    struct io_tcpc *client;

    client = arg;

    assert(client->state == IO_TCPC_STATE_CONNECTED
        || client->state == IO_TCPC_STATE_DISCONNECTING);

    if (events & IO_EVENT_FD_READ) {
        ssize_t ret;

        ret = c_buffer_read(client->rbuf, client->sock, BUFSIZ);
        if (ret == -1) {
            io_tcpc_signal_error(client, "cannot read socket: %s",
                                 c_get_error());

            io_tcpc_close(client);
            io_tcpc_signal_event(client, IO_TCPC_EVENT_CONNECTION_CLOSED);
            return;
        } else if (ret == 0) {
            io_tcpc_close(client);
            io_tcpc_signal_event(client, IO_TCPC_EVENT_CONNECTION_LOST);
            return;
        }

        io_tcpc_signal_event(client, IO_TCPC_EVENT_DATA_READ);

        /* The event callback may have closed the client; in that case, we
         * must not try to process any write event. */
        if (client->state == IO_TCPC_EVENT_CONNECTION_CLOSED)
            return;
    }

    if (events & IO_EVENT_FD_WRITE) {
        if (c_buffer_write(client->wbuf, client->sock) == -1) {
            io_tcpc_signal_error(client, "cannot write socket: %s",
                                 strerror(errno));

            io_tcpc_close(client);
            io_tcpc_signal_event(client, IO_TCPC_EVENT_CONNECTION_CLOSED);
            return;
        }

        if (c_buffer_length(client->wbuf) == 0) {
            if (client->state == IO_TCPC_STATE_DISCONNECTING) {
                io_tcpc_close(client);
                io_tcpc_signal_event(client, IO_TCPC_EVENT_CONNECTION_CLOSED);
                return;
            }

            if (io_tcpc_watch(client, IO_EVENT_FD_READ) == -1) {
                io_tcpc_signal_error(client, "%s", c_get_error());

                io_tcpc_close(client);
                io_tcpc_signal_event(client, IO_TCPC_EVENT_CONNECTION_CLOSED);
                return;
            }
        }
    }
}
