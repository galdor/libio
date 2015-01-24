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

#include "io.h"

/* ------------------------------------------------------------------------
 *  Event multiplexing
 * ------------------------------------------------------------------------ */
/* Watcher */
enum io_watcher_type {
    IO_WATCHER_FD,
    IO_WATCHER_SIGNAL,
};

uint64_t io_watcher_key_fd(int);
uint64_t io_watcher_key_signo(int);

struct io_watcher {
    enum io_watcher_type type;
    uint32_t events; /* enum io_event */
    uint64_t key;

    void *cb_arg;

    union {
        int fd;
        struct {
            int signo;
            io_signal_callback cb;

#ifdef IO_PLATFORM_LINUX
            int fd;
#endif
        } signal;
    } u;
};

struct io_watcher *io_watcher_new(enum io_watcher_type);
void io_watcher_delete(struct io_watcher *);

void io_watcher_free_backend(struct io_watcher *);

void io_watcher_on_events(struct io_watcher *, uint32_t);

/* Base */
struct io_base {
    int fd;

    struct c_hash_table *watchers;
};

int io_base_init_backend(struct io_base *);
void io_base_free_backend(struct io_base *);

int io_base_enable_watcher_signal_backend(struct io_base *,
                                          struct io_watcher *);
int io_base_disable_watcher_signal_backend(struct io_base *,
                                           struct io_watcher *);

int io_base_read_events_backend(struct io_base *);

/* ------------------------------------------------------------------------
 *  Utils
 * ------------------------------------------------------------------------ */
uint32_t io_hash_uint64_ptr(const void *);
bool io_equal_uint64_ptr(const void *, const void *);

#endif
