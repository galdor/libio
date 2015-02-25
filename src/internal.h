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
#include <limits.h>
#include <signal.h>
#include <string.h>

#include <net/if.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "io.h"

/* ------------------------------------------------------------------------
 *  Event multiplexing
 * ------------------------------------------------------------------------ */
/* Watcher */
enum io_watcher_type {
    IO_WATCHER_FD,
    IO_WATCHER_SIGNAL,
    IO_WATCHER_TIMER,
    IO_WATCHER_CHILD,
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

        struct {
            pid_t pid;
            io_child_callback cb;
            int event_value;
        } child;
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
    struct c_hash_table *child_watchers;

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
 *  SSL
 * ------------------------------------------------------------------------ */
const char *io_ssl_get_error(void);

DH *io_ssl_dh_load(const char *);

SSL_CTX *io_ssl_ctx_new_client(const char *, const char *);
SSL_CTX *io_ssl_ctx_new_server(const char *, const char *, const char *,
                               const char *);

SSL *io_ssl_new(SSL_CTX *, int);

/* ------------------------------------------------------------------------
 *  Messaging protocol
 * ------------------------------------------------------------------------ */
/* Message */
#define IO_MP_MSG_HEADER_SZ 12 /* bytes */

struct io_mp_msg {
    uint8_t op;
    uint8_t type  :  2; /* enum io_mp_msg_type */
    uint8_t flags :  6; /* enum io_mp_msg_flag */

    uint32_t id;

    void *payload;
    size_t payload_sz;
    bool owns_payload;

    void *payload_data;
    io_mp_msg_payload_data_free_func payload_data_free_func;
};

void io_mp_msg_init(struct io_mp_msg *);
void io_mp_msg_delete(struct io_mp_msg *);

struct io_mp_msg *io_mp_msg_new(void);
void io_mp_msg_delete(struct io_mp_msg *);

int io_mp_msg_decode(struct io_mp_msg *, const void *, size_t, size_t *);
void io_mp_msg_encode(const struct io_mp_msg *, struct c_buffer *);

/* Message callback */
struct io_mp_msg_callback_info {
    enum io_mp_msg_type msg_type;

    io_mp_msg_callback cb;
    void *cb_arg;
};

struct io_mp_msg_callback_info *
io_mp_msg_callback_info_new(enum io_mp_msg_type, io_mp_msg_callback, void *);
void io_mp_msg_callback_info_delete(struct io_mp_msg_callback_info *);

/* Message handler */
struct io_mp_msg_handler {
    struct c_hash_table *callbacks; /* op -> callback_info */
};

struct io_mp_msg_handler *io_mp_msg_handler_new(void);
void io_mp_msg_handler_delete(struct io_mp_msg_handler *);

void io_mp_msg_handler_bind_op(struct io_mp_msg_handler *,
                               uint8_t, enum io_mp_msg_type,
                               io_mp_msg_callback, void *);
void io_mp_msg_handler_unbind_op(struct io_mp_msg_handler *, uint8_t);

/* Response handler */
struct io_mp_response_handler {
    struct c_hash_table *callbacks; /* msg id -> callback_info */
};

struct io_mp_response_handler *io_mp_response_handler_new(void);
void io_mp_response_handler_delete(struct io_mp_response_handler *);

int io_mp_response_handler_add_callback(struct io_mp_response_handler *,
                                        uint32_t,
                                        io_mp_msg_callback, void *);
void io_mp_response_handler_remove_callback(struct io_mp_response_handler *,
                                            uint32_t);
struct io_mp_msg_callback_info *
io_mp_response_handler_get_callback(const struct io_mp_response_handler *,
                                    uint32_t);

/* Connections */
enum io_mp_connection_type {
    IO_MP_CONNECTION_TYPE_CLIENT,
    IO_MP_CONNECTION_TYPE_SERVER
};

enum io_mp_connection_state {
    IO_MP_CONNECTION_STATE_INACTIVE,
    IO_MP_CONNECTION_STATE_SSL_ACCEPTING,
    IO_MP_CONNECTION_STATE_ESTABLISHED,
    IO_MP_CONNECTION_STATE_CLOSING,
};

struct io_mp_connection {
    struct io_base *base;

    enum io_mp_connection_type type;
    enum io_mp_connection_state state;

    struct io_address address;
    int sock;

    struct c_buffer *rbuf;
    struct c_buffer *wbuf;

    bool do_close;

    bool ssl_enabled;
    SSL *ssl;
    size_t ssl_last_write_length;

    uint32_t last_msg_id;

    struct io_mp_response_handler *response_handler;

    void *private_data;

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

struct io_mp_msg_handler *
io_mp_connection_msg_handler(const struct io_mp_connection *);

int io_mp_connection_get_socket_error(struct io_mp_connection *, int *);

void io_mp_connection_trace(struct io_mp_connection *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));
void io_mp_connection_error(struct io_mp_connection *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));

int io_mp_connection_watch_read(struct io_mp_connection *);
int io_mp_connection_watch_write(struct io_mp_connection *);
int io_mp_connection_watch_read_write(struct io_mp_connection *);

int io_mp_connection_ssl_accept(struct io_mp_connection *);
int io_mp_connection_ssl_read(struct io_mp_connection *);
int io_mp_connection_ssl_write(struct io_mp_connection *);

int io_mp_connection_send_msg(struct io_mp_connection *,
                              const struct io_mp_msg *);

void io_mp_connection_on_event(int, uint32_t, void *);
int io_mp_connection_on_event_read(struct io_mp_connection *);
int io_mp_connection_on_event_write(struct io_mp_connection *);

int io_mp_connection_process_msg(struct io_mp_connection *, struct io_mp_msg *);
int io_mp_connection_process_notification_request(struct io_mp_connection *,
                                                  struct io_mp_msg *);
int io_mp_connection_process_response(struct io_mp_connection *,
                                      struct io_mp_msg *);

/* Client */
enum io_mp_client_state {
    IO_MP_CLIENT_STATE_INACTIVE,
    IO_MP_CLIENT_STATE_CONNECTING,
    IO_MP_CLIENT_STATE_SSL_CONNECTING,
    IO_MP_CLIENT_STATE_CONNECTED,
    IO_MP_CLIENT_STATE_WAITING_RECONNECTION,
};

struct io_mp_client {
    struct io_base *base;

    enum io_mp_client_state state;

    char host[NI_MAXHOST];
    uint16_t port;

    struct io_mp_connection *connection;

    int reconnection_timer;
    uint64_t reconnection_delay;

    bool ssl_enabled;
    char *ssl_ciphers;
    char ssl_ca_certificate_path[PATH_MAX];
    SSL_CTX *ssl_ctx;

    io_mp_connection_event_callback event_cb;
    void *event_cb_arg;
    io_mp_msg_callback msg_cb;
    void *msg_cb_arg;

    struct io_mp_msg_handler *msg_handler;
};

void io_mp_client_signal_event(struct io_mp_client *,
                               enum io_mp_connection_event, void *);
void io_mp_client_trace(struct io_mp_client *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));
void io_mp_client_error(struct io_mp_client *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));

void io_mp_client_disconnect(struct io_mp_client *);
void io_mp_client_reset(struct io_mp_client *);
void io_mp_client_schedule_reconnection(struct io_mp_client *);

int io_mp_client_ssl_connect(struct io_mp_client *);

int io_mp_client_on_event(struct io_mp_client *, uint32_t);
int io_mp_client_on_event_ssl_connecting(struct io_mp_client *);
int io_mp_client_on_event_write_connecting(struct io_mp_client *);
void io_mp_client_on_reconnection_timer(int, uint64_t, void *);

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

    SSL_CTX *ssl_ctx;
    bool ssl_enabled;
    char *ssl_ciphers;
    char ssl_private_key_path[PATH_MAX];
    char ssl_certificate_path[PATH_MAX];
    char ssl_dh_parameters_path[PATH_MAX];

    struct c_hash_table *connections; /* fd -> connection */

    io_mp_connection_event_callback event_cb;
    void *event_cb_arg;
    io_mp_msg_callback msg_cb;
    void *msg_cb_arg;

    struct io_mp_msg_handler *msg_handler;
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

uint32_t io_hash_pid_ptr(const void *);
bool io_equal_pid_ptr(const void *, const void *);

#endif
