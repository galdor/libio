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

#ifndef LIBIO_IO_H
#define LIBIO_IO_H

#include <sys/socket.h>
#include <sys/types.h>

#include <core.h>

/* ------------------------------------------------------------------------
 *  Addresses
 * ------------------------------------------------------------------------ */
#define IO_ADDRESS_HOST_BUFSIZ (39 + 2 + 1)
#define IO_ADDRESS_HOST_PORT_BUFSIZ (39 + 2 + 1 + 5 + 1)

struct io_address {
    struct sockaddr_storage ss;
    socklen_t sslen;

    char host_string[IO_ADDRESS_HOST_BUFSIZ];
    char host_port_string[IO_ADDRESS_HOST_BUFSIZ];
};

int io_address_init(struct io_address *, const char *, uint16_t);
int io_address_init_from_sockaddr(struct io_address *,
                                  const struct sockaddr *, socklen_t);
int io_address_init_from_sockaddr_storage(struct io_address *,
                                          const struct sockaddr_storage *);

int io_address_family(const struct io_address *);
uint16_t io_address_port(const struct io_address *);
const char *io_address_host_string(const struct io_address *);
const char *io_address_host_port_string(const struct io_address *);

struct sockaddr *io_address_sockaddr(const struct io_address *);
socklen_t io_address_length(const struct io_address *);

void io_address_set_port(struct io_address *, uint16_t);

/* ------------------------------------------------------------------------
 *  File descriptors
 * ------------------------------------------------------------------------ */
int io_fd_set_blocking(int);
int io_fd_set_non_blocking(int);

/* ------------------------------------------------------------------------
 *  Time
 * ------------------------------------------------------------------------ */
int io_read_monotonic_clock_ms(uint64_t *);

/* ------------------------------------------------------------------------
 *  Timers
 * ------------------------------------------------------------------------ */
enum io_timer_flag {
    IO_TIMER_RECURRENT = (1 << 0),
};

/* ------------------------------------------------------------------------
 *  Event multiplexing
 * ------------------------------------------------------------------------ */
enum io_event {
    IO_EVENT_FD_READ         = (1 << 0),
    IO_EVENT_FD_WRITE        = (1 << 1),
    IO_EVENT_FD_HANGUP       = (1 << 2),

    IO_EVENT_SIGNAL_RECEIVED = (1 << 3),

    IO_EVENT_TIMER_EXPIRED   = (1 << 4),

    IO_EVENT_CHILD_EXITED    = (1 << 5),
    IO_EVENT_CHILD_SIGNALED  = (1 << 6),
    IO_EVENT_CHILD_ABORTED   = (1 << 7),
};

typedef void (*io_signal_callback)(int, void *);
typedef void (*io_fd_callback)(int, uint32_t, void *);
typedef void (*io_timer_callback)(int, uint64_t, void *);
typedef void (*io_child_callback)(pid_t, uint32_t, int, void *);

struct io_base *io_base_new(void);
void io_base_delete(struct io_base *);

int io_base_fd(const struct io_base *);

int io_base_watch_fd(struct io_base *, int, uint32_t, io_fd_callback, void *);
int io_base_unwatch_fd(struct io_base *, int);
bool io_base_is_fd_watched(const struct io_base *, int);

int io_base_watch_signal(struct io_base *, int, io_signal_callback, void *);
int io_base_unwatch_signal(struct io_base *, int);
bool io_base_is_signal_watched(const struct io_base *, int);
int io_base_watch_sigchld(struct io_base *);
int io_base_unwatch_sigchld(struct io_base *);
int io_base_block_sigchld(struct io_base *);
int io_base_unblock_sigchld(struct io_base *);

int io_base_add_timer(struct io_base *, uint64_t, uint32_t,
                      io_timer_callback, void *);
int io_base_remove_timer(struct io_base *, int);

int io_base_watch_child(struct io_base *, pid_t, io_child_callback, void *);
int io_base_unwatch_child(struct io_base *, pid_t);
bool io_base_is_child_watched(const struct io_base *, pid_t);
void io_base_sigchld_handler(int, void *);

bool io_base_has_watchers(const struct io_base *);
int io_base_read_events(struct io_base *);

/* ------------------------------------------------------------------------
 *  SSL
 * ------------------------------------------------------------------------ */
void io_ssl_initialize(void);
void io_ssl_shutdown(void);

/* ------------------------------------------------------------------------
 *  Messaging protocol
 * ------------------------------------------------------------------------ */
/* Message */
struct io_mp_msg;

typedef void (*io_mp_msg_payload_data_free_func)(void *);

enum io_mp_msg_type {
    IO_MP_MSG_TYPE_UNUSED       = 0,
    IO_MP_MSG_TYPE_NOTIFICATION = 1,
    IO_MP_MSG_TYPE_REQUEST      = 2,
    IO_MP_MSG_TYPE_RESPONSE     = 3,
};

enum io_mp_msg_flag {
    IO_MP_MSG_FLAG_DEFAULT = 0,
};

uint8_t io_mp_msg_op(const struct io_mp_msg *);
enum io_mp_msg_type io_mp_msg_type(const struct io_mp_msg *);
uint32_t io_mp_msg_id(const struct io_mp_msg *);
const void *io_mp_msg_payload(const struct io_mp_msg *, size_t *);
void *io_mp_msg_payload_data(const struct io_mp_msg *);
size_t io_mp_msg_payload_size(const struct io_mp_msg *);

void io_mp_msg_set_payload_data(struct io_mp_msg *, void *,
                                io_mp_msg_payload_data_free_func);

/* Connection */
struct io_mp_connection;

enum io_mp_connection_event {
    IO_MP_CONNECTION_EVENT_TRACE,
    IO_MP_CONNECTION_EVENT_ERROR,
    IO_MP_CONNECTION_EVENT_FAILED, /* client only */
    IO_MP_CONNECTION_EVENT_ESTABLISHED,
    IO_MP_CONNECTION_EVENT_LOST,
};

typedef void (*io_mp_connection_event_callback)(struct io_mp_connection *,
                                                enum io_mp_connection_event,
                                                void *, void *);

typedef int (*io_mp_msg_callback)(struct io_mp_connection *,
                                  struct io_mp_msg *, void *);

struct io_mp_client *io_mp_connection_client(const struct io_mp_connection *);
struct io_mp_server *io_mp_connection_server(const struct io_mp_connection *);

void io_mp_connection_close(struct io_mp_connection *);

void io_mp_connection_set_private_data(struct io_mp_connection *, void *);
void *io_mp_connection_private_data(const struct io_mp_connection *);

int io_mp_connection_notify(struct io_mp_connection *, uint8_t, uint8_t,
                            const void *, size_t);
int io_mp_connection_request(struct io_mp_connection *, uint8_t, uint8_t,
                             const void *, size_t,
                             io_mp_msg_callback, void *);
int io_mp_connection_reply2(struct io_mp_connection *,
                            uint8_t, uint32_t, uint8_t,
                            const void *, size_t);
int io_mp_connection_reply(struct io_mp_connection *,
                           const struct io_mp_msg *, uint8_t,
                           const void *, size_t);

/* Client */
struct io_mp_client;

struct io_mp_client *io_mp_client_new(struct io_base *);
void io_mp_client_delete(struct io_mp_client *);

struct io_mp_connection *io_mp_client_connection(const struct io_mp_client *);
bool io_mp_client_is_connected(const struct io_mp_client *);

void io_mp_client_set_event_callback(struct io_mp_client *,
                                     io_mp_connection_event_callback,
                                     void *);
void io_mp_client_set_msg_callback(struct io_mp_client *,
                                   io_mp_msg_callback, void *);

int io_mp_client_enable_ssl(struct io_mp_client *, const char *);

int io_mp_client_connect(struct io_mp_client *, const char *, uint16_t);
void io_mp_client_close(struct io_mp_client *);

void io_mp_client_bind_op(struct io_mp_client *, uint8_t, enum io_mp_msg_type,
                          io_mp_msg_callback, void *);
void io_mp_client_unbind_op(struct io_mp_client *, uint8_t);

/* Server */
struct io_mp_server;

struct io_mp_server *io_mp_server_new(struct io_base *);
void io_mp_server_delete(struct io_mp_server *);

void io_mp_server_set_event_callback(struct io_mp_server *,
                                     io_mp_connection_event_callback,
                                     void *);
void io_mp_server_set_msg_callback(struct io_mp_server *,
                                   io_mp_msg_callback, void *);

int io_mp_server_enable_ssl(struct io_mp_server *,
                            const char *, const char *, const char *);

int io_mp_server_listen(struct io_mp_server *, const char *, uint16_t);

void io_mp_server_bind_op(struct io_mp_server *, uint8_t, enum io_mp_msg_type,
                          io_mp_msg_callback, void *);
void io_mp_server_unbind_op(struct io_mp_server *, uint8_t);

#endif
