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

int io_address_resolve(const char *, uint16_t, sa_family_t, int, int,
                       struct io_address **, size_t *);

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

int io_fd_set_cloexec(int);

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

typedef void (*io_signal_cb)(int, void *);
typedef void (*io_fd_cb)(int, uint32_t, void *);
typedef void (*io_timer_cb)(int, uint64_t, void *);
typedef void (*io_child_cb)(pid_t, uint32_t, int, void *);

struct io_base *io_base_new(void);
void io_base_delete(struct io_base *);

int io_base_fd(const struct io_base *);

int io_base_watch_fd(struct io_base *, int, uint32_t, io_fd_cb, void *);
int io_base_unwatch_fd(struct io_base *, int);
bool io_base_is_fd_watched(const struct io_base *, int);

int io_base_watch_signal(struct io_base *, int, io_signal_cb, void *);
int io_base_unwatch_signal(struct io_base *, int);
bool io_base_is_signal_watched(const struct io_base *, int);
int io_base_watch_sigchld(struct io_base *);
int io_base_unwatch_sigchld(struct io_base *);
int io_base_block_sigchld(struct io_base *);
int io_base_unblock_sigchld(struct io_base *);

int io_base_add_timer(struct io_base *, uint64_t, uint32_t,
                      io_timer_cb, void *);
int io_base_remove_timer(struct io_base *, int);

int io_base_watch_child(struct io_base *, pid_t, io_child_cb, void *);
int io_base_unwatch_child(struct io_base *, pid_t);
bool io_base_is_child_watched(const struct io_base *, pid_t);
void io_base_sigchld_handler(int, void *);

bool io_base_has_watchers(const struct io_base *);
int io_base_read_events(struct io_base *);

/* ------------------------------------------------------------------------
 *  TCP client
 * ------------------------------------------------------------------------ */
enum io_tcpc_event {
    IO_TCPC_EVENT_CONNECTION_FAILED,
    IO_TCPC_EVENT_CONNECTION_ESTABLISHED,
    IO_TCPC_EVENT_CONNECTION_CLOSED,
    IO_TCPC_EVENT_CONNECTION_LOST,
    IO_TCPC_EVENT_ERROR,
    IO_TCPC_EVENT_DATA_READ,
};

struct io_tcpc;

typedef void (*io_tcpc_event_cb)(struct io_tcpc *, enum io_tcpc_event, void *);

struct io_tcpc *io_tcpc_new(struct io_base *, io_tcpc_event_cb, void *);
void io_tcpc_delete(struct io_tcpc *);

struct c_buffer *io_tcpc_rbuf(const struct io_tcpc *);

int io_tcpc_connect(struct io_tcpc *, const char *, uint16_t);
void io_tcpc_disconnect(struct io_tcpc *);
void io_tcpc_close(struct io_tcpc *);

int io_tcpc_write(struct io_tcpc *, const void *, size_t);

/* ------------------------------------------------------------------------
 *  TCP server
 * ------------------------------------------------------------------------ */
enum io_tcps_event {
    IO_TCPS_EVENT_SERVER_LISTENING,
    IO_TCPS_EVENT_SERVER_STOPPED,
    IO_TCPS_EVENT_CONNECTION_ACCEPTED,
    IO_TCPS_EVENT_CONNECTION_CLOSED,
    IO_TCPS_EVENT_CONNECTION_LOST,
    IO_TCPS_EVENT_ERROR,
    IO_TCPS_EVENT_DATA_READ,
};

struct io_tcps;
struct io_tcpsc;

typedef void (*io_tcps_event_cb)(struct io_tcps *, struct io_tcpsc *,
                                 enum io_tcps_event, void *);

struct io_tcps *io_tcps_new(struct io_base *, io_tcps_event_cb, void *);
void io_tcps_delete(struct io_tcps *);

int io_tcps_listen(struct io_tcps *, const char *, uint16_t);
void io_tcps_stop(struct io_tcps *);
void io_tcps_close(struct io_tcps *);

void io_tcpsc_disconnect(struct io_tcpsc *);
void io_tcpsc_close(struct io_tcpsc *);
struct c_buffer *io_tcpsc_rbuf(const struct io_tcpsc *);
int io_tcpsc_write(struct io_tcpsc *, const void *, size_t);

#endif
