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
 *  Event multiplexing
 * ------------------------------------------------------------------------ */
enum io_event {
    IO_EVENT_FD_READ,
    IO_EVENT_FD_WRITE,
    IO_EVENT_FD_HANGHUP,
    IO_EVENT_FD_ERROR,

    IO_EVENT_SIGNAL_RECEIVED,
};

typedef void (*io_signal_callback)(int, void *);

struct io_base *io_base_new(void);
void io_base_delete(struct io_base *);

int io_base_watch_signal(struct io_base *, int, io_signal_callback, void *);
int io_base_unwatch_signal(struct io_base *, int);

bool io_base_has_watchers(const struct io_base *);
int io_base_read_events(struct io_base *);

#endif
