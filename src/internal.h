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

#ifndef LIBIO_INTERNAL_H
#define LIBIO_INTERNAL_H

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>

#include <net/if.h>

#include "io.h"

/* ------------------------------------------------------------------------
 *  Event multiplexing
 * ------------------------------------------------------------------------ */
/* Watcher */
enum io_watcher_type {
    IO_WATCHER_FD,
    IO_WATCHER_SIGNAL,
    IO_WATCHER_TIMER,
};

struct io_watcher {
    struct io_base *base;

    enum io_watcher_type type;
    uint32_t events; /* enum io_event */

    bool registered;
    bool enabled;
    bool in_callback;

    void *cb_arg;

    union {
        struct {
            int fd;
            io_fd_callback cb;
        } fd;

        struct {
            int signo;
            io_signal_callback cb;

#ifdef IO_PLATFORM_LINUX
            int fd;
#endif
        } signal;

        struct {
            int id;
            io_timer_callback cb;

            uint64_t duration; /* milliseconds */
            uint32_t flags; /* enum io_timer_flag */

            uint64_t start_time; /* millisecond monotonic clock */

            bool expired;

#ifdef IO_PLATFORM_LINUX
            int fd;
#endif
        } timer;
    } u;
};

struct io_watcher *io_watcher_new(struct io_base *, enum io_watcher_type);
void io_watcher_delete(struct io_watcher *);

void io_watcher_free_backend(struct io_watcher *);

int io_watcher_on_events(struct io_watcher *, uint32_t);

/* Watcher arrays */
struct io_watcher_array {
    struct io_watcher **watchers;
    size_t nb_watchers;
    size_t size;
};

void io_watcher_array_init(struct io_watcher_array *);
void io_watcher_array_free(struct io_watcher_array *);

void io_watcher_array_add(struct io_watcher_array *, int, struct io_watcher *);
void io_watcher_array_remove(struct io_watcher_array *, int);
struct io_watcher *io_watcher_array_get(const struct io_watcher_array *, int);

/* Base */
struct io_base {
    int fd;

    struct io_watcher_array fd_watchers;
    struct io_watcher_array signal_watchers;
    struct io_watcher_array timer_watchers;

    int last_timer_id;
    struct c_heap *free_timer_ids;
};

int io_base_generate_timer_id(struct io_base *);
void io_base_release_timer_id(struct io_base *, int);

int io_base_init_backend(struct io_base *);
void io_base_free_backend(struct io_base *);

int io_base_enable_fd_backend(struct io_base *, struct io_watcher *);
int io_base_disable_fd_backend(struct io_base *, struct io_watcher *);

int io_base_enable_signal_backend(struct io_base *, struct io_watcher *);
int io_base_disable_signal_backend(struct io_base *, struct io_watcher *);

int io_base_enable_timer_backend(struct io_base *, struct io_watcher *);
int io_base_disable_timer_backend(struct io_base *, struct io_watcher *);

int io_base_read_events_backend(struct io_base *);

/* ------------------------------------------------------------------------
 *  Messaging protocol
 * ------------------------------------------------------------------------ */
/* Message */
#define IO_MP_MSG_HEADER_SZ 12 /* bytes */

enum io_mp_msg_type {
    IO_MP_MSG_TYPE_UNUSED       = 0,
    IO_MP_MSG_TYPE_NOTIFICATION = 1,
    IO_MP_MSG_TYPE_REQUEST      = 2,
    IO_MP_MSG_TYPE_RESPONSE     = 3,
};

struct io_mp_msg {
    uint8_t op;
    uint8_t type    :  2; /* enum io_mp_msg_type */
    uint8_t flags   :  6; /* enum io_mp_msg_flag */

    uint32_t id;

    void *payload;
    size_t payload_sz;

    bool owns_payload;
};

void io_mp_msg_init(struct io_mp_msg *);
void io_mp_msg_delete(struct io_mp_msg *);

struct io_mp_msg *io_mp_msg_new(void);
void io_mp_msg_delete(struct io_mp_msg *);

int io_mp_msg_decode(struct io_mp_msg *, const void *, size_t, size_t *);
void io_mp_msg_encode(const struct io_mp_msg *, struct c_buffer *);

/* Connections */
enum io_mp_connection_type {
    IO_MP_CONNECTION_TYPE_CLIENT,
    IO_MP_CONNECTION_TYPE_SERVER
};

struct io_mp_connection {
    struct io_base *base;
    io_fd_callback event_callback;

    enum io_mp_connection_type type;

    struct io_address address;
    int sock;

    struct c_buffer *rbuf;
    struct c_buffer *wbuf;

    bool closed;

    uint32_t last_msg_id;

    union {
        struct {
            struct io_mp_client *client;
        } client;

        struct {
            struct io_mp_listener *listener;
        } server;
    } u;
};

struct io_mp_connection *io_mp_connection_new(void);
struct io_mp_connection *io_mp_connection_new_client(struct io_mp_client *,
                                                     int);
struct io_mp_connection *io_mp_connection_new_server(struct io_mp_listener *);
void io_mp_connection_delete(struct io_mp_connection *);

int io_mp_connection_get_socket_error(struct io_mp_connection *, int *);

void io_mp_connection_trace(struct io_mp_connection *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));

int io_mp_connection_watch_read(struct io_mp_connection *);
int io_mp_connection_watch_read_write(struct io_mp_connection *);

int io_mp_connection_send_msg(struct io_mp_connection *,
                              const struct io_mp_msg *);

void io_mp_connection_on_event(int, uint32_t, void *);
int io_mp_connection_on_event_read(struct io_mp_connection *);
int io_mp_connection_on_event_write(struct io_mp_connection *);

/* Client */
enum io_mp_client_state {
    IO_MP_CLIENT_STATE_INACTIVE,
    IO_MP_CLIENT_STATE_CONNECTING,
    IO_MP_CLIENT_STATE_CONNECTED,
};

struct io_mp_client {
    struct io_base *base;

    enum io_mp_client_state state;

    struct io_mp_connection *connection;

    void *private_data;
    io_mp_connection_event_callback event_callback;
};

void io_mp_client_signal_event(struct io_mp_client *,
                               enum io_mp_connection_event, void *);
void io_mp_client_trace(struct io_mp_client *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));
void io_mp_client_error(struct io_mp_client *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));

void io_mp_client_reset(struct io_mp_client *);

int io_mp_client_on_event(struct io_mp_client *, uint32_t);
int io_mp_client_on_event_write_connecting(struct io_mp_client *);

/* Listener */
struct io_mp_listener {
    struct io_mp_server *server;

    char iface[IFNAMSIZ];
    struct io_address address;

    int sock;
};

struct io_mp_listener *io_mp_listener_new(struct io_mp_server *);
void io_mp_listener_delete(struct io_mp_listener *);

int io_mp_listener_listen(struct io_mp_listener *, const char *,
                          const struct io_address *);

void io_mp_listener_on_event(int, uint32_t, void *);

/* Server */
struct io_mp_server {
    struct io_base *base;

    struct io_mp_listener **listeners;
    size_t nb_listeners;

    struct c_hash_table *connections; /* fd -> connection */

    void *private_data;
    io_mp_connection_event_callback event_callback;
};

void io_mp_server_signal_event(struct io_mp_server *,
                               struct io_mp_connection *,
                               enum io_mp_connection_event, void *);
void io_mp_server_trace(struct io_mp_server *, struct io_mp_connection *,
                        const char *, ...)
    __attribute__ ((format(printf, 3, 4)));
void io_mp_server_error(struct io_mp_server *, struct io_mp_connection *,
                        const char *, ...)
    __attribute__ ((format(printf, 3, 4)));

void io_mp_server_destroy_connection(struct io_mp_server *,
                                     struct io_mp_connection *);

int io_mp_server_on_event(struct io_mp_server *, struct io_mp_connection *,
                          uint32_t);

/* ------------------------------------------------------------------------
 *  Utils
 * ------------------------------------------------------------------------ */
uint32_t io_hash_uint64_ptr(const void *);
bool io_equal_uint64_ptr(const void *, const void *);

#endif
