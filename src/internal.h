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
    IO_WATCHER_TIMER,
};

struct io_watcher {
    enum io_watcher_type type;
    uint32_t events; /* enum io_event */

    bool registered;

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
            uint64_t expiration_time; /* millisecond monotonic clock */

            bool expired;

#ifdef IO_PLATFORM_LINUX
            int fd;
#endif
        } timer;
    } u;
};

struct io_watcher *io_watcher_new(enum io_watcher_type);
void io_watcher_delete(struct io_watcher *);

void io_watcher_free_backend(struct io_watcher *);

void io_watcher_on_events(struct io_watcher *, uint32_t);

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
};

void io_base_add_fd_watcher(struct io_base *, struct io_watcher *);
void io_base_remove_fd_watcher(struct io_base *, struct io_watcher *);

void io_base_add_signal_watcher(struct io_base *, struct io_watcher *);
void io_base_remove_signal_watcher(struct io_base *, struct io_watcher *);

void io_base_add_timer_watcher(struct io_base *, struct io_watcher *);
void io_base_remove_timer_watcher(struct io_base *, struct io_watcher *);

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
 *  Utils
 * ------------------------------------------------------------------------ */
uint32_t io_hash_uint64_ptr(const void *);
bool io_equal_uint64_ptr(const void *, const void *);

#endif
