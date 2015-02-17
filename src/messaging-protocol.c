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

#include <netinet/in.h>
#include <unistd.h>

#include <ifaddrs.h>

#include "internal.h"

static uint32_t io_mp_read_u32(const uint8_t *);
static void io_mp_write_u32(uint32_t, uint8_t *);

/* ------------------------------------------------------------------------
 *  Message
 * ------------------------------------------------------------------------ */
void
io_mp_msg_init(struct io_mp_msg *msg) {
    memset(msg, 0, sizeof(struct io_mp_msg));
}

void
io_mp_msg_free(struct io_mp_msg *msg) {
    if (!msg)
        return;

    if (msg->owns_payload)
        c_free(msg->payload);

    if (msg->payload_data)
        msg->payload_data_free_func(msg->payload_data);

    memset(msg, 0, sizeof(struct io_mp_msg));
}

struct io_mp_msg *
io_mp_msg_new(void) {
    struct io_mp_msg *msg;

    msg = c_malloc(sizeof(struct io_mp_msg));

    io_mp_msg_init(msg);

    return msg;
}

void
io_mp_msg_delete(struct io_mp_msg *msg) {
    if (!msg)
        return;

    io_mp_msg_free(msg);

    c_free(msg);
}

uint8_t
io_mp_msg_op(const struct io_mp_msg *msg) {
    return msg->op;
}

enum io_mp_msg_type
io_mp_msg_type(const struct io_mp_msg *msg) {
    return msg->type;
}

uint32_t
io_mp_msg_id(const struct io_mp_msg *msg) {
    return msg->id;
}

const void *
io_mp_msg_payload(const struct io_mp_msg *msg, size_t *psz) {
    if (psz)
        *psz = msg->payload_sz;

    return msg->payload;
}

void *
io_mp_msg_payload_data(const struct io_mp_msg *msg) {
    return msg->payload_data;
}

void
io_mp_msg_set_payload_data(struct io_mp_msg *msg, void *data,
                           io_mp_msg_payload_data_free_func free_func) {
    if (msg->payload_data)
        msg->payload_data_free_func(msg->payload_data);

    msg->payload_data = data;
    msg->payload_data_free_func = free_func ? free_func : c_free;
}

int
io_mp_msg_decode(struct io_mp_msg *msg, const void *data, size_t sz,
                 size_t *psz) {
    const uint8_t *ptr;
    size_t len;

    ptr = data;
    len = sz;

    /* Header */
    if (len < IO_MP_MSG_HEADER_SZ)
        return 0;

    msg->op = ptr[0];
    msg->type = (ptr[1] & 0xc0) >> 6;
    msg->flags = (ptr[1] & 0x30);
    msg->payload_sz = io_mp_read_u32(ptr + 4);
    msg->id = io_mp_read_u32(ptr + 8);

    if (msg->op == IO_MP_MSG_TYPE_UNUSED) {
        c_set_error("invalid message type %d", msg->op);
        return -1;
    }

    ptr += IO_MP_MSG_HEADER_SZ;
    len -= IO_MP_MSG_HEADER_SZ;

    /* Payload */
    if (len < msg->payload_sz)
        return 0;

    msg->payload = (void *)ptr;

    msg->owns_payload = false;

    ptr += msg->payload_sz;
    len -= msg->payload_sz;

    if (psz)
        *psz = sz - len;
    return 1;
}

void
io_mp_msg_encode(const struct io_mp_msg *msg, struct c_buffer *buf) {
    size_t msg_sz;
    uint8_t *ptr;

    msg_sz = IO_MP_MSG_HEADER_SZ + msg->payload_sz;
    ptr = c_buffer_reserve(buf, msg_sz);

    ptr[0] = msg->op;
    ptr[1] = (msg->type << 6) | msg->flags;
    ptr[2] = 0;
    ptr[3] = 0;
    io_mp_write_u32(msg->payload_sz, ptr + 4);
    io_mp_write_u32(msg->id, ptr + 8);

    if (msg->payload_sz > 0)
        memcpy(ptr + IO_MP_MSG_HEADER_SZ, msg->payload, msg->payload_sz);

    c_buffer_increase_length(buf, msg_sz);
}

/* ------------------------------------------------------------------------
 *  Message callback
 * ------------------------------------------------------------------------ */
struct io_mp_msg_callback_info *
io_mp_msg_callback_info_new(enum io_mp_msg_type msg_type,
                            io_mp_msg_callback cb, void *cb_arg) {
    struct io_mp_msg_callback_info *info;

    info = c_malloc0(sizeof(struct io_mp_msg_callback_info));

    info->msg_type = msg_type;

    info->cb = cb;
    info->cb_arg = cb_arg;

    return info;
}

void
io_mp_msg_callback_info_delete(struct io_mp_msg_callback_info *info) {
    if (!info)
        return;

    c_free0(info, sizeof(struct io_mp_msg_callback_info));
}

/* ------------------------------------------------------------------------
 *  Message handler
 * ------------------------------------------------------------------------ */
struct io_mp_msg_handler *
io_mp_msg_handler_new(void) {
    struct io_mp_msg_handler *handler;

    handler = c_malloc0(sizeof(struct io_mp_msg_handler));

    handler->callbacks = c_hash_table_new(c_hash_int32, c_equal_int32);

    return handler;
}

void
io_mp_msg_handler_delete(struct io_mp_msg_handler *handler) {
    struct c_hash_table_iterator *it;
    struct io_mp_msg_callback_info *info;

    if (!handler)
        return;

    it = c_hash_table_iterate(handler->callbacks);
    while (c_hash_table_iterator_next(it, NULL, (void **)&info) == 1) {
        io_mp_msg_callback_info_delete(info);
    }
    c_hash_table_iterator_delete(it);
    c_hash_table_delete(handler->callbacks);

    c_free0(handler, sizeof(struct io_mp_msg_handler));
}

void
io_mp_msg_handler_bind_op(struct io_mp_msg_handler *handler,
                          uint8_t op, enum io_mp_msg_type type,
                          io_mp_msg_callback cb, void *cb_arg) {
    struct io_mp_msg_callback_info *info, *old;

    info = io_mp_msg_callback_info_new(type, cb, cb_arg);

    if (c_hash_table_insert2(handler->callbacks, C_INT32_TO_POINTER(op), info,
                             NULL, (void **)&old) == 0) {
        io_mp_msg_callback_info_delete(old);
    }
}

void
io_mp_msg_handler_unbind_op(struct io_mp_msg_handler *handler,
                            uint8_t op) {
    struct io_mp_msg_callback_info *info;

    if (c_hash_table_remove2(handler->callbacks, C_INT32_TO_POINTER(op),
                             NULL, (void **)&info) == 1) {
        io_mp_msg_callback_info_delete(info);
    }
}

struct io_mp_msg_callback_info *
io_mp_msg_handler_get_callback(const struct io_mp_msg_handler *handler,
                               uint8_t op) {
    struct io_mp_msg_callback_info *info;

    if (c_hash_table_get(handler->callbacks, C_INT32_TO_POINTER(op),
                         (void **)&info) == 0) {
        return NULL;
    }

    return info;
}

/* ------------------------------------------------------------------------
 *  Response handler
 * ------------------------------------------------------------------------ */
struct io_mp_response_handler *
io_mp_response_handler_new(void) {
    struct io_mp_response_handler *handler;

    handler = c_malloc0(sizeof(struct io_mp_response_handler));

    handler->callbacks = c_hash_table_new(c_hash_int32, c_equal_int32);

    return handler;
}

void
io_mp_response_handler_delete(struct io_mp_response_handler *handler) {
    struct c_hash_table_iterator *it;
    struct io_mp_msg_callback_info *info;

    if (!handler)
        return;

    it = c_hash_table_iterate(handler->callbacks);
    while (c_hash_table_iterator_next(it, NULL, (void **)&info) == 1) {
        io_mp_msg_callback_info_delete(info);
    }
    c_hash_table_iterator_delete(it);
    c_hash_table_delete(handler->callbacks);

    c_free0(handler, sizeof(struct io_mp_response_handler));
}

int
io_mp_response_handler_add_callback(struct io_mp_response_handler *handler,
                                    uint32_t id,
                                    io_mp_msg_callback cb, void *cb_arg) {
    struct io_mp_msg_callback_info *info;

    if (c_hash_table_contains(handler->callbacks,
                              C_INT32_TO_POINTER(id))) {
        c_set_error("duplicate request identifier");
        return -1;
    }

    info = io_mp_msg_callback_info_new(IO_MP_MSG_TYPE_RESPONSE, cb, cb_arg);

    c_hash_table_insert(handler->callbacks,
                        C_INT32_TO_POINTER(id), info);

    return 0;
}

void
io_mp_response_handler_remove_callback(struct io_mp_response_handler *handler,
                                       uint32_t id) {
    struct io_mp_msg_callback_info *info;

    if (c_hash_table_remove2(handler->callbacks,
                             C_INT32_TO_POINTER(id),
                             NULL, (void **)&info) == 1) {
        io_mp_msg_callback_info_delete(info);
    }
}

struct io_mp_msg_callback_info *
io_mp_response_handler_get_callback(const struct io_mp_response_handler *handler,
                                    uint32_t id) {
    struct io_mp_msg_callback_info *info;

    if (c_hash_table_get(handler->callbacks, C_INT32_TO_POINTER(id),
                         (void **)&info) == 0) {
        return NULL;
    }

    return info;
}

/* ------------------------------------------------------------------------
 *  Connection
 * ------------------------------------------------------------------------ */
struct io_mp_connection *
io_mp_connection_new(void) {
    struct io_mp_connection *connection;

    connection = c_malloc0(sizeof(struct io_mp_connection));

    connection->state = IO_MP_CONNECTION_STATE_INACTIVE;

    connection->rbuf = c_buffer_new();
    connection->wbuf = c_buffer_new();

    connection->response_handler = io_mp_response_handler_new();

    return connection;
}

struct io_mp_connection *
io_mp_connection_new_client(struct io_mp_client *client, int sock) {
    struct io_mp_connection *connection;

    connection = io_mp_connection_new();

    connection->base = client->base;
    connection->type = IO_MP_CONNECTION_TYPE_CLIENT;
    connection->sock = sock;
    connection->u.client.client = client;

    return connection;
}

struct io_mp_connection *
io_mp_connection_new_server(struct io_mp_listener *listener) {
    struct io_mp_connection *connection;

    connection = io_mp_connection_new();

    connection->base = listener->server->base;
    connection->type = IO_MP_CONNECTION_TYPE_SERVER;
    connection->sock = -1;
    connection->u.server.listener = listener;

    return connection;
}

void
io_mp_connection_delete(struct io_mp_connection *connection) {
    if (!connection)
        return;

    if (connection->ssl)
        SSL_free(connection->ssl);

    if (connection->sock >= 0) {
        io_base_unwatch_fd(connection->base, connection->sock);
        close(connection->sock);
    }

    c_buffer_delete(connection->rbuf);
    c_buffer_delete(connection->wbuf);

    io_mp_response_handler_delete(connection->response_handler);

    c_free0(connection, sizeof(struct io_mp_connection));
}

struct io_mp_client *
io_mp_connection_client(const struct io_mp_connection *connection) {
    assert(connection->type == IO_MP_CONNECTION_TYPE_CLIENT);

    return connection->u.client.client;
}

struct io_mp_server *
io_mp_connection_server(const struct io_mp_connection *connection) {
    assert(connection->type == IO_MP_CONNECTION_TYPE_SERVER);

    return connection->u.server.listener->server;
}

void
io_mp_connection_close(struct io_mp_connection *connection) {
    if (connection->state == IO_MP_CONNECTION_STATE_ESTABLISHED) {
        if (io_mp_connection_watch_write(connection) == -1) {
            io_mp_connection_error(connection, "%s", c_get_error());
            connection->do_close = true;
            return;
        }

        if (shutdown(connection->sock, SHUT_RD) == -1) {
            io_mp_connection_error(connection, "cannot shut socket down: %s",
                                   strerror(errno));
            connection->do_close = true;
            return;
        }

        connection->state = IO_MP_CONNECTION_STATE_CLOSING;
    } else {
        /* Close asap */
        connection->do_close = true;
    }
}

struct io_mp_msg_handler *
io_mp_connection_msg_handler(const struct io_mp_connection *connection) {
    switch (connection->type) {
    case IO_MP_CONNECTION_TYPE_CLIENT:
        return connection->u.client.client->msg_handler;

    case IO_MP_CONNECTION_TYPE_SERVER:
        return connection->u.server.listener->server->msg_handler;

    default:
        return NULL;
    }
}

int
io_mp_connection_get_socket_error(struct io_mp_connection *connection,
                                  int *perror) {
    socklen_t len;

    *perror = 0;

    len = sizeof(int);
    if (getsockopt(connection->sock, SOL_SOCKET, SO_ERROR,
                   perror, &len) == -1) {
        c_set_error("cannot get socket error: %s", strerror(errno));
        return -1;
    }

    return 0;
}

void
io_mp_connection_trace(struct io_mp_connection *connection,
                       const char *fmt, ...) {
    char msg[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    if (connection->type == IO_MP_CONNECTION_TYPE_CLIENT) {
        io_mp_client_trace(connection->u.client.client, "%s", msg);
    } else if (connection->type == IO_MP_CONNECTION_TYPE_SERVER) {
        struct io_mp_listener *listener;

        listener = connection->u.server.listener;

        io_mp_server_trace(listener->server, connection, "%s", msg);
    }
}

void
io_mp_connection_error(struct io_mp_connection *connection,
                       const char *fmt, ...) {
    char msg[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    if (connection->type == IO_MP_CONNECTION_TYPE_CLIENT) {
        io_mp_client_error(connection->u.client.client, "%s", msg);
    } else if (connection->type == IO_MP_CONNECTION_TYPE_SERVER) {
        struct io_mp_listener *listener;

        listener = connection->u.server.listener;

        io_mp_server_error(listener->server, connection, "%s", msg);
    }
}

int
io_mp_connection_watch_read(struct io_mp_connection *connection) {
    if (io_base_watch_fd(connection->base, connection->sock,
                         IO_EVENT_FD_READ,
                         io_mp_connection_on_event, connection) == -1) {
        c_set_error("cannot watch socket events: %s", c_get_error());
    }

    return 0;
}

int
io_mp_connection_watch_write(struct io_mp_connection *connection) {
    if (io_base_watch_fd(connection->base, connection->sock,
                         IO_EVENT_FD_WRITE,
                         io_mp_connection_on_event, connection) == -1) {
        c_set_error("cannot watch socket events: %s", c_get_error());
    }

    return 0;
}

int
io_mp_connection_watch_read_write(struct io_mp_connection *connection) {
    if (io_base_watch_fd(connection->base, connection->sock,
                         IO_EVENT_FD_READ | IO_EVENT_FD_WRITE,
                         io_mp_connection_on_event, connection) == -1) {
        c_set_error("cannot watch socket events: %s", c_get_error());
    }

    return 0;
}

int
io_mp_connection_ssl_accept(struct io_mp_connection *connection) {
    struct io_mp_server *server;
    int ret;

    assert(connection->state == IO_MP_CONNECTION_STATE_SSL_ACCEPTING);
    assert(connection->type == IO_MP_CONNECTION_TYPE_SERVER);
    assert(connection->ssl_enabled);

    server = connection->u.server.listener->server;

    ret = SSL_accept(connection->ssl);
    if (ret != 1) {
        int err;

        err = SSL_get_error(connection->ssl, ret);

        switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return io_mp_connection_watch_read_write(connection);

        default:
            c_set_error("cannot accept ssl connection: %s", io_ssl_get_error());
            return -1;
        }
    }

    connection->state = IO_MP_CONNECTION_STATE_ESTABLISHED;

    io_mp_server_signal_event(server, connection,
                              IO_MP_CONNECTION_EVENT_ESTABLISHED, NULL);

    return 0;
}

int
io_mp_connection_ssl_read(struct io_mp_connection *connection) {
    static size_t read_sz = BUFSIZ;

    void *buf;
    int ret;

    assert(connection->ssl_enabled);

    buf = c_buffer_reserve(connection->rbuf, read_sz);

    ret = SSL_read(connection->ssl, buf, read_sz);
    if (ret <= 0) {
        const char *errmsg;
        int err;

        err = SSL_get_error(connection->ssl, ret);

        switch (err) {
        case SSL_ERROR_ZERO_RETURN:
            return 0;

        case SSL_ERROR_SYSCALL:
            if (errno == 0)
                return 0;

            errmsg = strerror(errno);
            break;

        default:
            errmsg = io_ssl_get_error();
            break;
        }

        c_set_error("cannot read ssl data: %s", io_ssl_get_error());
        return -1;
    }

    c_buffer_increase_length(connection->rbuf, (size_t)ret);
    return ret;
}

int
io_mp_connection_ssl_write(struct io_mp_connection *connection) {
    size_t length;
    int ret;

    assert(connection->ssl_enabled);

    if (connection->ssl_last_write_length > 0) {
        length = connection->ssl_last_write_length;
        assert(length >= c_buffer_length(connection->wbuf));
    } else {
        length = c_buffer_length(connection->wbuf);
    }

    ret = SSL_write(connection->ssl, c_buffer_data(connection->wbuf),
                    c_buffer_length(connection->wbuf));
    if (ret <= 0) {
        int err;

        err = SSL_get_error(connection->ssl, ret);

        connection->ssl_last_write_length = length;

        switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return io_mp_connection_watch_read_write(connection);

        default:
            c_set_error("cannot write ssl data: %s", io_ssl_get_error());
            return -1;
        }
    }

    c_buffer_skip(connection->wbuf, (size_t)ret);

    connection->ssl_last_write_length = 0;
    return ret;
}

int
io_mp_connection_send_msg(struct io_mp_connection *connection,
                          const struct io_mp_msg *msg) {
    assert(connection->state == IO_MP_CONNECTION_STATE_ESTABLISHED);
    assert(msg->payload_sz <= UINT32_MAX);

    io_mp_msg_encode(msg, connection->wbuf);

    if (io_mp_connection_watch_read_write(connection) == -1)
        return -1;

    return 0;
}

void
io_mp_connection_set_private_data(struct io_mp_connection *connection,
                                  void *data) {
    connection->private_data = data;
}

void *
io_mp_connection_private_data(const struct io_mp_connection *connection) {
    return connection->private_data;
}

int
io_mp_connection_notify(struct io_mp_connection *connection,
                        uint8_t op, uint8_t flags,
                        const void *payload, size_t payload_sz) {
    struct io_mp_msg msg;

    io_mp_msg_init(&msg);

    msg.op = op;
    msg.type = IO_MP_MSG_TYPE_NOTIFICATION;
    msg.flags = flags;
    msg.id = connection->last_msg_id + 1;

    msg.payload = (void *)payload;
    msg.payload_sz = payload_sz;

    if (io_mp_connection_send_msg(connection, &msg) == -1) {
        io_mp_msg_free(&msg);
        return -1;
    }

    io_mp_msg_free(&msg);

    connection->last_msg_id++;
    return 0;
}

int
io_mp_connection_request(struct io_mp_connection *connection,
                         uint8_t op, uint8_t flags,
                         const void *payload, size_t payload_sz,
                         io_mp_msg_callback cb, void *cb_arg) {
    struct io_mp_msg msg;
    uint32_t id;

    id = connection->last_msg_id + 1;

    if (io_mp_response_handler_add_callback(connection->response_handler,
                                            id, cb, cb_arg) == -1)
        return -1;

    io_mp_msg_init(&msg);

    msg.op = op;
    msg.type = IO_MP_MSG_TYPE_REQUEST;
    msg.flags = flags;
    msg.id = id;

    msg.payload = (void *)payload;
    msg.payload_sz = payload_sz;

    if (io_mp_connection_send_msg(connection, &msg) == -1) {
        io_mp_response_handler_remove_callback(connection->response_handler, id);
        io_mp_msg_free(&msg);
        return -1;
    }

    io_mp_msg_free(&msg);

    connection->last_msg_id++;
    return 0;
}

int
io_mp_connection_reply2(struct io_mp_connection *connection,
                        uint8_t op, uint32_t id, uint8_t flags,
                        const void *payload, size_t payload_sz) {
    struct io_mp_msg msg;

    io_mp_msg_init(&msg);

    msg.op = op;
    msg.type = IO_MP_MSG_TYPE_RESPONSE;
    msg.flags = flags;
    msg.id = id;

    msg.payload = (void *)payload;
    msg.payload_sz = payload_sz;

    if (io_mp_connection_send_msg(connection, &msg) == -1) {
        io_mp_msg_free(&msg);
        return -1;
    }

    io_mp_msg_free(&msg);
    return 0;
}

int
io_mp_connection_reply(struct io_mp_connection *connection,
                       const struct io_mp_msg *request_msg,
                       uint8_t flags,
                       const void *payload, size_t payload_sz) {
    return io_mp_connection_reply2(connection, request_msg->op, request_msg->id,
                                   flags, payload, payload_sz);
}

void
io_mp_connection_on_event(int fd, uint32_t events, void *arg) {
    struct io_mp_connection *connection;

    connection = arg;

    if (connection->type == IO_MP_CONNECTION_TYPE_CLIENT) {
        struct io_mp_client *client;

        client = connection->u.client.client;

        if (io_mp_client_on_event(client, events) == -1) {
            io_mp_client_error(client, "%s", c_get_error());
            io_mp_client_disconnect(client);
            io_mp_client_schedule_reconnection(client);
            return;
        }

        if (connection->do_close) {
            io_mp_client_disconnect(client);
            io_mp_client_schedule_reconnection(client);
        }
    } else if (connection->type == IO_MP_CONNECTION_TYPE_SERVER) {
        struct io_mp_listener *listener;
        struct io_mp_server *server;

        listener = connection->u.server.listener;
        server = listener->server;

        if (io_mp_server_on_event(server, connection, events) == -1) {
            io_mp_server_error(server, connection, "%s", c_get_error());
            io_mp_connection_close(connection);
            return;
        }

        if (connection->do_close)
            io_mp_server_destroy_connection(server, connection);
    }
}

int
io_mp_connection_on_event_read(struct io_mp_connection *connection) {
    ssize_t ret;

    assert(connection->state == IO_MP_CONNECTION_STATE_ESTABLISHED);

    if (connection->ssl_enabled) {
        ret = io_mp_connection_ssl_read(connection);
    } else {
        ret = c_buffer_read(connection->rbuf, connection->sock, BUFSIZ);
    }

    if (ret == -1) {
        c_set_error("cannot read socket: %s", c_get_error());
        return -1;
    } else if (ret == 0) {
        io_mp_connection_trace(connection, "connection closed by peer");
        connection->do_close = true;
        return 0;
    }

#if 0
    io_mp_connection_trace(connection, "%zd bytes read", ret);
#endif

    for (;;) {
        struct io_mp_msg msg;
        const char *data;
        size_t read_sz, sz;
        int ret;

        data = c_buffer_data(connection->rbuf);
        sz = c_buffer_length(connection->rbuf);

        io_mp_msg_init(&msg);

        ret = io_mp_msg_decode(&msg, data, sz, &read_sz);
        if (ret == -1) {
            c_set_error("cannot decode message: %s", c_get_error());
            return -1;
        } else if (ret == 0) {
            return 0;
        }

        io_mp_connection_trace(connection,
                               "msg: op 0x%02x, type %u, id 0x%08x payload sz %zu",
                               msg.op, msg.type, msg.id, msg.payload_sz);

        if (io_mp_connection_process_msg(connection, &msg) == -1) {
            io_mp_msg_free(&msg);
            return -1;
        }

        io_mp_msg_free(&msg);

        c_buffer_skip(connection->rbuf, read_sz);
    }

    return 0;
}

int
io_mp_connection_on_event_write(struct io_mp_connection *connection) {
    ssize_t ret;

    assert(connection->state == IO_MP_CONNECTION_STATE_ESTABLISHED
        || connection->state == IO_MP_CONNECTION_STATE_CLOSING);

    if (connection->ssl_enabled) {
        ret = io_mp_connection_ssl_write(connection);
    } else {
        ret = c_buffer_write(connection->wbuf, connection->sock);
    }

    if (ret == -1) {
        c_set_error("cannot write to socket: %s", c_get_error());
        return -1;
    }

#if 0
    if (ret > 0)
        io_mp_connection_trace(connection, "%zd bytes written", ret);
#endif

    if (c_buffer_length(connection->wbuf) == 0) {
        if (io_mp_connection_watch_read(connection) == -1)
            return -1;

        if (connection->state == IO_MP_CONNECTION_STATE_CLOSING)
            connection->do_close = true;
    }

    return 0;
}

int
io_mp_connection_process_msg(struct io_mp_connection *connection,
                             struct io_mp_msg *msg) {
    io_mp_msg_callback msg_cb;
    void *msg_cb_arg;
    int ret;

    switch (connection->type) {
    case IO_MP_CONNECTION_TYPE_CLIENT:
        msg_cb = connection->u.client.client->msg_cb;
        msg_cb_arg = connection->u.client.client->msg_cb_arg;
        break;

    case IO_MP_CONNECTION_TYPE_SERVER:
        msg_cb = connection->u.server.listener->server->msg_cb;
        msg_cb_arg = connection->u.server.listener->server->msg_cb_arg;
        break;
    }

    if (msg_cb) {
        if (msg_cb(connection, msg, msg_cb_arg) == -1) {
            c_set_error("error while processing message 0x%02x: %s",
                        msg->op, c_get_error());
            return -1;
        }

        if (connection->state == IO_MP_CONNECTION_STATE_CLOSING)
            return 0;

        if (connection->do_close)
            return 0;
    }

    switch (msg->type) {
    case IO_MP_MSG_TYPE_UNUSED:
        c_set_error("invalid message type %u", msg->type);
        return -1;

    case IO_MP_MSG_TYPE_NOTIFICATION:
    case IO_MP_MSG_TYPE_REQUEST:
        ret = io_mp_connection_process_notification_request(connection, msg);
        break;

    case IO_MP_MSG_TYPE_RESPONSE:
        ret = io_mp_connection_process_response(connection, msg);
        break;
    }

    return ret;
}

int
io_mp_connection_process_notification_request(struct io_mp_connection *connection,
                                              struct io_mp_msg *msg) {
    const struct io_mp_msg_callback_info *info;
    const struct io_mp_msg_handler *handler;

    assert(msg->type == IO_MP_MSG_TYPE_NOTIFICATION
        || msg->type == IO_MP_MSG_TYPE_REQUEST);

    handler = io_mp_connection_msg_handler(connection);

    info = io_mp_msg_handler_get_callback(handler, msg->op);
    if (!info) {
        c_set_error("unhandled op 0x%02x", msg->op);
        return -1;
    }

    if (msg->type != info->msg_type) {
        c_set_error("message type mismatch");
        return -1;
    }

    if (info->cb(connection, msg, info->cb_arg) == -1) {
        const char *type_string;

        if (msg->type == IO_MP_MSG_TYPE_NOTIFICATION) {
            type_string = "notification";
        } else {
            type_string = "request";
        }
        c_set_error("error while processing %s 0x%02x: %s",
                    type_string, msg->op, c_get_error());
        return -1;
    }

    return 0;
}

int
io_mp_connection_process_response(struct io_mp_connection *connection,
                                  struct io_mp_msg *msg) {
    const struct io_mp_msg_callback_info *info;

    assert(msg->type == IO_MP_MSG_TYPE_RESPONSE);

    info = io_mp_response_handler_get_callback(connection->response_handler,
                                               msg->id);
    if (!info) {
        c_set_error("unknown message id %#08x", msg->id);
        return -1;
    }

    if (info->cb) {
        if (info->cb(connection, msg, info->cb_arg) == -1) {
            c_set_error("error while processing response 0x%02x: %s",
                        msg->op, c_get_error());
            return -1;
        }
    }

    io_mp_response_handler_remove_callback(connection->response_handler,
                                           msg->id);
    return 0;
}

/* ------------------------------------------------------------------------
 *  Client
 * ------------------------------------------------------------------------ */
struct io_mp_client *
io_mp_client_new(struct io_base *base) {
    struct io_mp_client *client;

    client = c_malloc0(sizeof(struct io_mp_client));

    client->base = base;
    client->state = IO_MP_CLIENT_STATE_INACTIVE;

    client->reconnection_timer = -1;
    client->reconnection_delay = 1000;

    client->msg_handler = io_mp_msg_handler_new();

    return client;
}

void
io_mp_client_delete(struct io_mp_client *client) {
    if (!client)
        return;

    io_mp_client_reset(client);

    if (client->ssl_ctx)
        SSL_CTX_free(client->ssl_ctx);
    c_free(client->ssl_ciphers);

    io_mp_msg_handler_delete(client->msg_handler);

    c_free0(client, sizeof(struct io_mp_client));
}

struct io_mp_connection *
io_mp_client_connection(const struct io_mp_client *client) {
    assert(client->state == IO_MP_CLIENT_STATE_CONNECTED);

    return client->connection;
}

bool
io_mp_client_is_connected(const struct io_mp_client *client) {
    return client->state == IO_MP_CLIENT_STATE_CONNECTED;
}

void
io_mp_client_set_event_callback(struct io_mp_client *client,
                                io_mp_connection_event_callback cb,
                                void *cb_arg) {
    client->event_cb = cb;
    client->event_cb_arg = cb_arg;
}

void
io_mp_client_set_msg_callback(struct io_mp_client *client,
                                io_mp_msg_callback cb,
                                void *cb_arg) {
    client->msg_cb = cb;
    client->msg_cb_arg = cb_arg;
}

int
io_mp_server_enable_ssl(struct io_mp_server *server,
                        const char *private_key_path,
                        const char *certificate_path,
                        const char *dh_parameters_path) {
    if (!server->ssl_ciphers)
        server->ssl_ciphers = c_strdup("HIGH:@STRENGTH");

    if (c_strlcpy(server->ssl_private_key_path, private_key_path,
                  PATH_MAX) >= PATH_MAX) {
        c_set_error("private key path too long");
        return -1;
    }

    if (c_strlcpy(server->ssl_certificate_path, certificate_path,
                  PATH_MAX) >= PATH_MAX) {
        c_set_error("certificate path too long");
        return -1;
    }

    if (c_strlcpy(server->ssl_dh_parameters_path, dh_parameters_path,
                  PATH_MAX) >= PATH_MAX) {
        c_set_error("dh parameters path too long");
        return -1;
    }

    server->ssl_ctx = io_ssl_ctx_new_server(server->ssl_ciphers,
                                            server->ssl_private_key_path,
                                            server->ssl_certificate_path,
                                            server->ssl_dh_parameters_path);
    if (!server->ssl_ctx) {
        c_set_error("cannot create ssl context: %s", c_get_error());
        return -1;
    }

    io_mp_server_error(server, NULL, "ssl enabled");
    io_mp_server_error(server, NULL, "using ssl ciphers %s",
                       server->ssl_ciphers);
    io_mp_server_error(server, NULL, "using ssl private key from %s",
                       private_key_path);
    io_mp_server_error(server, NULL, "using ssl certificate from %s",
                       certificate_path);
    io_mp_server_error(server, NULL, "using ssl dh parameters from %s",
                       dh_parameters_path);

    server->ssl_enabled = true;
    return 0;
}

void
io_mp_client_signal_event(struct io_mp_client *client,
                          enum io_mp_connection_event event, void *data) {
    if (!client->event_cb)
        return;

    client->event_cb(client->connection, event, data, client->event_cb_arg);
}

void
io_mp_client_trace(struct io_mp_client *client, const char *fmt, ...) {
    char msg[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    io_mp_client_signal_event(client, IO_MP_CONNECTION_EVENT_TRACE, msg);
}

void
io_mp_client_error(struct io_mp_client *client, const char *fmt, ...) {
    char msg[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    io_mp_client_signal_event(client, IO_MP_CONNECTION_EVENT_ERROR, msg);
}

int
io_mp_client_enable_ssl(struct io_mp_client *client,
                        const char *ca_certificate_path) {
    assert(client->state == IO_MP_CLIENT_STATE_INACTIVE);

    if (!client->ssl_ciphers)
        client->ssl_ciphers = c_strdup("HIGH:@STRENGTH");

    if (c_strlcpy(client->ssl_ca_certificate_path, ca_certificate_path,
                  PATH_MAX) >= PATH_MAX) {
        c_set_error("ssl ca path too long");
        return -1;
    }

    if (client->ssl_ctx)
        SSL_CTX_free(client->ssl_ctx);

    client->ssl_ctx = io_ssl_ctx_new_client(client->ssl_ciphers,
                                            client->ssl_ca_certificate_path);
    if (!client->ssl_ctx) {
        c_set_error("cannot create ssl context: %s", c_get_error());
        return -1;
    }

    client->ssl_enabled = true;

    io_mp_client_trace(client, "ssl enabled");
    io_mp_client_trace(client, "using ssl ciphers %s", client->ssl_ciphers);
    io_mp_client_trace(client, "using ssl ca certificate from %s",
                       client->ssl_ca_certificate_path);

    return 0;
}

void
io_mp_client_reset(struct io_mp_client *client) {
    io_mp_connection_delete(client->connection);
    client->connection = NULL;

    if (client->reconnection_timer >= 0) {
        io_base_remove_timer(client->base, client->reconnection_timer);
        client->reconnection_timer = -1;
    }

    client->state = IO_MP_CLIENT_STATE_INACTIVE;

    io_mp_client_trace(client, "client reset"); /* XXX remove */
}

void
io_mp_client_schedule_reconnection(struct io_mp_client *client) {
    int timer;

    assert(client->state == IO_MP_CLIENT_STATE_INACTIVE);

    io_mp_client_trace(client, "scheduling reconnection");

    timer = io_base_add_timer(client->base, client->reconnection_delay,
                              0, io_mp_client_on_reconnection_timer, client);
    if (timer == -1) {
        c_set_error("cannot create timer: %s", c_get_error());
        io_mp_client_error(client, "cannot create timer: %s", c_get_error());
        io_mp_client_reset(client);
        return;
    }

    client->reconnection_timer = timer;
    client->state = IO_MP_CLIENT_STATE_WAITING_RECONNECTION;
}

int
io_mp_client_connect(struct io_mp_client *client,
                     const char *host, uint16_t port) {
    struct io_address address;
    int sock;

    assert(client->state == IO_MP_CLIENT_STATE_INACTIVE);

    if (c_strlcpy(client->host, host, NI_MAXHOST) >= NI_MAXHOST) {
        c_set_error("hostname too long");
        return -1;
    }

    client->port = port;

    if (io_address_init(&address, host, port) == -1) {
        c_set_error("cannot initialize address: %s", c_get_error());
        goto error;
    }

    sock = socket(io_address_family(&address), SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1) {
        c_set_error("cannot create socket: %s", strerror(errno));
        goto error;
    }

    if (io_fd_set_non_blocking(sock) == -1)
        goto error;

    io_mp_client_trace(client, "connecting to %s",
                       io_address_host_port_string(&address));

    if (connect(sock, io_address_sockaddr(&address),
                io_address_length(&address)) == -1) {
        if (errno != EINPROGRESS) {
            c_set_error("cannot connect socket: %s", strerror(errno));
            goto error;
        }
    }

    client->connection = io_mp_connection_new_client(client, sock);
    memcpy(&client->connection->address, &address, sizeof(struct io_address));

    client->connection->ssl_enabled = client->ssl_enabled;

    if (io_mp_connection_watch_read_write(client->connection) == -1)
        goto error;

    client->state = IO_MP_CLIENT_STATE_CONNECTING;
    return 0;

error:
    io_mp_client_reset(client);
    return -1;
}

int
io_mp_client_ssl_connect(struct io_mp_client *client) {
    struct io_mp_connection *connection;
    int ret;

    assert(client->state == IO_MP_CLIENT_STATE_SSL_CONNECTING);
    assert(client->ssl_enabled);

    connection = client->connection;

    ret = SSL_connect(connection->ssl);
    if (ret != 1) {
        int err;

        err = SSL_get_error(connection->ssl, ret);

        switch (err) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            if (io_mp_connection_watch_read_write(connection) == -1)
                return -1;
            break;

        default:
            c_set_error("cannot establish ssl connection: %s",
                        io_ssl_get_error());
            return -1;
        }
    }

    client->state = IO_MP_CLIENT_STATE_CONNECTED;
    client->connection->state = IO_MP_CONNECTION_STATE_ESTABLISHED;

    io_mp_client_signal_event(client, IO_MP_CONNECTION_EVENT_ESTABLISHED, NULL);

    return 0;
}

void
io_mp_client_close(struct io_mp_client *client) {
    if (client->connection)
        io_mp_connection_close(client->connection);
}

void
io_mp_client_disconnect(struct io_mp_client *client) {
    bool is_connected;

    is_connected = (client->state == IO_MP_CLIENT_STATE_CONNECTED);

    if (is_connected)
        io_mp_client_trace(client, "disconnecting");

    io_mp_client_reset(client); /* -> IO_MP_CLIENT_STATE_INACTIVE */

    if (is_connected)
        io_mp_client_signal_event(client, IO_MP_CONNECTION_EVENT_LOST, NULL);
}

void
io_mp_client_bind_op(struct io_mp_client *client,
                     uint8_t op, enum io_mp_msg_type msg_type,
                     io_mp_msg_callback cb, void *cb_arg) {
    io_mp_msg_handler_bind_op(client->msg_handler, op, msg_type,
                              cb, cb_arg);
}

void
io_mp_client_unbind_op(struct io_mp_client *client, uint8_t op) {
    io_mp_msg_handler_unbind_op(client->msg_handler, op);
}

int
io_mp_client_on_event(struct io_mp_client *client, uint32_t events) {
    int ret;

    ret = 0;

    if (events & IO_EVENT_FD_READ) {
        switch (client->state) {
        case IO_MP_CLIENT_STATE_INACTIVE:
        case IO_MP_CLIENT_STATE_CONNECTING:
        case IO_MP_CLIENT_STATE_WAITING_RECONNECTION:
            /* Should not happen */
            break;

        case IO_MP_CLIENT_STATE_SSL_CONNECTING:
            ret = io_mp_client_on_event_ssl_connecting(client);
            break;

        case IO_MP_CLIENT_STATE_CONNECTED:
            ret = io_mp_connection_on_event_read(client->connection);
            break;
        }

        if (ret == -1)
            return -1;
    }

    if (events & IO_EVENT_FD_WRITE) {
        switch (client->state) {
        case IO_MP_CLIENT_STATE_INACTIVE:
        case IO_MP_CLIENT_STATE_WAITING_RECONNECTION:
            /* Should not happen */
            break;

        case IO_MP_CLIENT_STATE_SSL_CONNECTING:
            ret = io_mp_client_on_event_ssl_connecting(client);
            break;

        case IO_MP_CLIENT_STATE_CONNECTING:
            ret = io_mp_client_on_event_write_connecting(client);
            break;

        case IO_MP_CLIENT_STATE_CONNECTED:
            ret = io_mp_connection_on_event_write(client->connection);
            break;
        }

        if (ret == -1)
            return -1;
    }

    return 0;
}

int
io_mp_client_on_event_write_connecting(struct io_mp_client *client) {
    struct io_mp_connection *connection;
    int err;

    assert(client->state == IO_MP_CLIENT_STATE_CONNECTING);

    connection = client->connection;

    if (io_mp_connection_get_socket_error(connection, &err) == -1)
        return -1;

    if (err != 0) {
        c_set_error("cannot connect to %s: %s",
                    io_address_host_port_string(&connection->address),
                    strerror(err));

        io_mp_client_signal_event(client, IO_MP_CONNECTION_EVENT_FAILED,
                                  strerror(err));
        return -1;
    }

    if (io_mp_connection_watch_read(connection) == -1)
        return -1;

    io_mp_client_trace(client, "connected to %s",
                       io_address_host_port_string(&connection->address));

    if (client->ssl_enabled) {
        connection->ssl = io_ssl_new(client->ssl_ctx, connection->sock);
        if (!connection->ssl) {
            c_set_error("cannot create ssl connection: %s", c_get_error());
            return -1;
        }

        client->state = IO_MP_CLIENT_STATE_SSL_CONNECTING;

        if (io_mp_client_ssl_connect(client) == -1)
            return -1;
    } else {
        client->state = IO_MP_CLIENT_STATE_CONNECTED;
        connection->state = IO_MP_CONNECTION_STATE_ESTABLISHED;

        io_mp_client_signal_event(client, IO_MP_CONNECTION_EVENT_ESTABLISHED, NULL);
    }

    return 0;
}

int
io_mp_client_on_event_ssl_connecting(struct io_mp_client *client) {
    return io_mp_client_ssl_connect(client);
}

void
io_mp_client_on_reconnection_timer(int timer, uint64_t delay, void *arg) {
    struct io_mp_client *client;

    client = arg;

    assert(client->state == IO_MP_CLIENT_STATE_WAITING_RECONNECTION);

    client->reconnection_timer = -1;

    client->state = IO_MP_CLIENT_STATE_INACTIVE;

    if (io_mp_client_connect(client, client->host, client->port) == -1) {
        io_mp_client_error(client, "cannot reconnect: %s", c_get_error());
        io_mp_client_reset(client);
        return;
    }
}

/* ------------------------------------------------------------------------
 *  Listener
 * ------------------------------------------------------------------------ */
struct io_mp_listener *
io_mp_listener_new(struct io_mp_server *server) {
    struct io_mp_listener *listener;

    listener = c_malloc0(sizeof(struct io_mp_listener));

    listener->server = server;
    listener->sock = -1;

    return listener;
}

void
io_mp_listener_delete(struct io_mp_listener *listener) {
    if (!listener)
        return;

    if (listener->sock >= 0)
        close(listener->sock);

    c_free0(listener, sizeof(struct io_mp_listener));
}

int
io_mp_listener_listen(struct io_mp_listener *listener, const char *iface,
                      const struct io_address *address) {
    struct io_mp_server *server;
    int opt;

    assert(listener->sock == -1);

    server = listener->server;

    if (c_strlcpy(listener->iface, iface, IFNAMSIZ) >= IFNAMSIZ) {
        c_set_error("interface name too long");
        return -1;
    }

    listener->address = *address;

    /* Create the socket */
    listener->sock = socket(io_address_family(address),
                            SOCK_STREAM, IPPROTO_TCP);
    if (listener->sock == -1) {
        c_set_error("cannot create socket: %s", strerror(errno));
        return -1;
    }

    opt = 1;
    if (setsockopt(listener->sock, SOL_SOCKET, SO_REUSEADDR,
                   &opt, sizeof(int)) == -1) {
        c_set_error("cannot set SO_REUSEADDR: %s", strerror(errno));
        return -1;
    }

    /* Listen for connections */
    if (bind(listener->sock,
             io_address_sockaddr(address), io_address_length(address)) == -1) {
        c_set_error("cannot bind socket to %s: %s",
                    io_address_host_port_string(address), strerror(errno));
        return -1;
    }

    if (listen(listener->sock, 10) == -1) {
        c_set_error("cannot listen on socket: %s", strerror(errno));
        return -1;
    }

    if (io_base_watch_fd(server->base, listener->sock, IO_EVENT_FD_READ,
                         io_mp_listener_on_event, listener) == -1) {
        c_set_error("cannot watch socket: %s", c_get_error());
        return -1;
    }

    return 0;
}

void
io_mp_listener_on_event(int fd, uint32_t events, void *arg) {
    struct io_mp_connection *connection;
    struct io_mp_listener *listener;
    struct io_mp_server *server;
    struct sockaddr_storage ss;
    socklen_t ss_len;

    assert(events & IO_EVENT_FD_READ);

    listener = arg;
    server = listener->server;

    connection = io_mp_connection_new_server(listener);

    /* Accept the connection */
    ss_len = sizeof(struct sockaddr_storage);
    connection->sock = accept(listener->sock, (struct sockaddr *)&ss, &ss_len);
    if (connection->sock == -1) {
        c_set_error("cannot accept connection: %s", strerror(errno));
        goto error;
    }

    if (io_address_init_from_sockaddr_storage(&connection->address,
                                              &ss) == -1) {
        c_set_error("cannot initialize address: %s", c_get_error());
        goto error;
    }

    io_mp_server_trace(server, NULL, "connection from %s",
                       io_address_host_port_string(&connection->address));

    if (io_fd_set_non_blocking(connection->sock) == -1)
        goto error;

    /* Watch for events */
    if (io_mp_connection_watch_read(connection) == -1)
        goto error;

    /* SSL */
    if (server->ssl_enabled) {
        connection->ssl = io_ssl_new(server->ssl_ctx, connection->sock);
        if (!connection->ssl) {
            c_set_error("cannot create ssl connection: %s", c_get_error());
            goto error;
        }

        connection->ssl_enabled = true;

        connection->state = IO_MP_CONNECTION_STATE_SSL_ACCEPTING;

        if (io_mp_connection_ssl_accept(connection) == -1)
            goto error;
    } else {
        connection->state = IO_MP_CONNECTION_STATE_ESTABLISHED;
    }

    /* Register the connection */
    c_hash_table_insert(server->connections,
                        C_INT32_TO_POINTER(connection->sock), connection);

    io_mp_server_signal_event(server, connection,
                              IO_MP_CONNECTION_EVENT_ESTABLISHED, NULL);

    return;

error:
    io_mp_server_error(server, NULL,
                       "cannot accept connection: %s", c_get_error());
    io_mp_connection_delete(connection);
}

/* ------------------------------------------------------------------------
 *  Server
 * ------------------------------------------------------------------------ */
struct io_mp_server *
io_mp_server_new(struct io_base *base) {
    struct io_mp_server *server;

    server = c_malloc0(sizeof(struct io_mp_server));

    server->base = base;
    server->connections = c_hash_table_new(c_hash_int32, c_equal_int32);

    server->msg_handler = io_mp_msg_handler_new();

    return server;
}

void
io_mp_server_delete(struct io_mp_server *server) {
    struct c_hash_table_iterator *it;
    struct io_mp_connection *connection;

    if (!server)
        return;

    if (server->ssl_ctx)
        SSL_CTX_free(server->ssl_ctx);
    c_free(server->ssl_ciphers);

    it = c_hash_table_iterate(server->connections);
    while (c_hash_table_iterator_next(it, NULL, (void **)&connection) == 1) {
        io_mp_server_signal_event(server, connection,
                                  IO_MP_CONNECTION_EVENT_LOST, NULL);
        io_mp_connection_delete(connection);
    }
    c_hash_table_iterator_delete(it);
    c_hash_table_delete(server->connections);

    for (size_t i = 0; i < server->nb_listeners; i++)
        io_mp_listener_delete(server->listeners[i]);
    c_free(server->listeners);

    io_mp_msg_handler_delete(server->msg_handler);

    c_free0(server, sizeof(struct io_mp_server));
}

void
io_mp_server_set_event_callback(struct io_mp_server *server,
                                io_mp_connection_event_callback cb,
                                void *cb_arg) {
    server->event_cb = cb;
    server->event_cb_arg = cb_arg;
}

void
io_mp_server_set_msg_callback(struct io_mp_server *server,
                                io_mp_msg_callback cb,
                                void *cb_arg) {
    server->msg_cb = cb;
    server->msg_cb_arg = cb_arg;
}

void
io_mp_server_signal_event(struct io_mp_server *server,
                          struct io_mp_connection *connection,
                          enum io_mp_connection_event event, void *data) {
    if (!server->event_cb)
        return;

    server->event_cb(connection, event, data, server->event_cb_arg);
}

void
io_mp_server_trace(struct io_mp_server *server,
                   struct io_mp_connection *connection, const char *fmt, ...) {
    char msg[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    io_mp_server_signal_event(server, connection,
                              IO_MP_CONNECTION_EVENT_TRACE, msg);
}

void
io_mp_server_error(struct io_mp_server *server,
                   struct io_mp_connection *connection, const char *fmt, ...) {
    char msg[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    io_mp_server_signal_event(server, connection,
                              IO_MP_CONNECTION_EVENT_ERROR, msg);
}

void
io_mp_server_destroy_connection(struct io_mp_server *server,
                                struct io_mp_connection *connection) {
    io_mp_server_signal_event(server, connection,
                              IO_MP_CONNECTION_EVENT_LOST, NULL);

    c_hash_table_remove(server->connections,
                        C_INT32_TO_POINTER(connection->sock));

    io_mp_connection_delete(connection);
}

int
io_mp_server_listen(struct io_mp_server *server,
                    const char *iface, uint16_t port) {
    struct ifaddrs *iaddrs, *iaddr;
    struct io_mp_listener *listener;
    size_t original_nb_listeners, nsz;

    iaddrs = NULL;
    original_nb_listeners = server->nb_listeners;

    if (getifaddrs(&iaddrs) == -1) {
        c_set_error("cannot get network interface info: %s", strerror(errno));
        return -1;
    }

    iaddr = iaddrs;
    while (iaddr) {
        struct io_address address;
        socklen_t salen;

        if (!(iaddr->ifa_flags & IFF_UP))
            goto next;

        if (strcmp(iaddr->ifa_name, iface) != 0)
            goto next;

        switch (iaddr->ifa_addr->sa_family) {
        case AF_INET:
            salen = sizeof(struct sockaddr_in);
            break;

        case AF_INET6:
            salen = sizeof(struct sockaddr_in6);
            break;

        default:
            goto next;
        }

        if (io_address_init_from_sockaddr(&address, iaddr->ifa_addr,
                                          salen) == -1) {
            goto error;
        }

        io_address_set_port(&address, port);

        listener = io_mp_listener_new(server);

        if (io_mp_listener_listen(listener, iface, &address) == -1) {
            io_mp_listener_delete(listener);
            goto error;
        }

        io_mp_server_trace(server, NULL, "listening on %s (%s)%s",
                           listener->iface,
                           io_address_host_port_string(&listener->address),
                           server->ssl_enabled ? " with ssl" : "");

        nsz = (server->nb_listeners + 1) * sizeof(struct io_mp_listener *);
        server->listeners = c_realloc(server->listeners, nsz);
        server->listeners[server->nb_listeners++] = listener;

next:
        iaddr = iaddr->ifa_next;
    }

    if (server->nb_listeners == original_nb_listeners) {
        c_set_error("no usable address found");
        goto error;
    }

    freeifaddrs(iaddrs);
    return 0;

error:
    if (iaddrs)
        freeifaddrs(iaddrs);

    for (size_t i = original_nb_listeners; i < server->nb_listeners; i++)
        io_mp_listener_delete(server->listeners[i]);

    if (original_nb_listeners > 0) {
        nsz = original_nb_listeners * sizeof(struct io_mp_listener *);
        server->listeners = c_realloc(server->listeners, nsz);
    } else {
        c_free(server->listeners);
        server->listeners = NULL;
    }

    server->nb_listeners = original_nb_listeners;
    return -1;
}

void
io_mp_server_bind_op(struct io_mp_server *server,
                     uint8_t op, enum io_mp_msg_type msg_type,
                     io_mp_msg_callback cb, void *cb_arg) {
    io_mp_msg_handler_bind_op(server->msg_handler, op, msg_type,
                              cb, cb_arg);
}

void
io_mp_server_unbind_op(struct io_mp_server *server, uint8_t op) {
    io_mp_msg_handler_unbind_op(server->msg_handler, op);
}

int
io_mp_server_on_event(struct io_mp_server *server,
                      struct io_mp_connection *connection, uint32_t events) {
    if (events & IO_EVENT_FD_READ) {
        if (io_mp_connection_on_event_read(connection) == -1)
            return -1;
    }

    if (events & IO_EVENT_FD_WRITE) {
        if (io_mp_connection_on_event_write(connection) == -1)
            return -1;
    }

    return 0;
}

/* ---------------------------------------------------------------------------
 *  Misc
 * ------------------------------------------------------------------------ */
static uint32_t
io_mp_read_u32(const uint8_t *ptr) {
    return ((uint32_t)ptr[0] << 24)
         | ((uint32_t)ptr[1] << 16)
         | ((uint32_t)ptr[2] <<  8)
         |  (uint32_t)ptr[3];
}

static void
io_mp_write_u32(uint32_t value, uint8_t *buf) {
    buf[0] = (value & 0xff000000) >> 24;
    buf[1] = (value & 0x00ff0000) >> 16;
    buf[2] = (value & 0x0000ff00) >>  8;
    buf[3] =  value & 0x000000ff;
}
