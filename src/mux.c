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

#include <unistd.h>

#include "internal.h"

/* ------------------------------------------------------------------------
 *  Watcher
 * ------------------------------------------------------------------------ */
uint64_t
io_watcher_key_fd(int fd) {
    return ((uint64_t)IO_WATCHER_FD << 32) | (uint64_t)fd;
}

uint64_t
io_watcher_key_signo(int signo) {
    return ((uint64_t)IO_WATCHER_SIGNAL << 32) | (uint64_t)signo;
}

struct io_watcher *
io_watcher_new(enum io_watcher_type type) {
    struct io_watcher *watcher;

    watcher = c_malloc0(sizeof(struct io_watcher));

    watcher->type = type;

    return watcher;
}

void
io_watcher_delete(struct io_watcher *watcher) {
    if (!watcher)
        return;

    io_watcher_free_backend(watcher);

    c_free0(watcher, sizeof(struct io_watcher));
}

void
io_watcher_on_events(struct io_watcher *watcher, uint32_t events) {
    switch (watcher->type) {
    case IO_WATCHER_FD:
        if (watcher->u.fd.cb)
            watcher->u.fd.cb(watcher->u.fd.fd, events, watcher->cb_arg);
        break;

    case IO_WATCHER_SIGNAL:
        if (watcher->u.signal.cb)
            watcher->u.signal.cb(watcher->u.signal.signo, watcher->cb_arg);
        break;
    }
}

/* ------------------------------------------------------------------------
 *  Base
 * ------------------------------------------------------------------------ */
struct io_base *
io_base_new(void) {
    struct io_base *base;

    base = c_malloc0(sizeof(struct io_base));

    if (io_base_init_backend(base) == -1) {
        io_base_delete(base);
        return NULL;
    }

    base->watchers = c_hash_table_new(io_hash_uint64_ptr, io_equal_uint64_ptr);

    return base;
}

void
io_base_delete(struct io_base *base) {
    struct c_hash_table_iterator *it;
    struct io_watcher *watcher;

    if (!base)
        return;

    it = c_hash_table_iterate(base->watchers);
    while (c_hash_table_iterator_next(it, NULL, (void **)&watcher) == 1)
        io_watcher_delete(watcher);
    c_hash_table_iterator_delete(it);
    c_hash_table_delete(base->watchers);

    io_base_free_backend(base);

    c_free0(base, sizeof(struct io_base));
}

int
io_base_watch_signal(struct io_base *base, int signo,
                     io_signal_callback cb, void *arg) {
    struct io_watcher *watcher;
    uint64_t key;

    key = io_watcher_key_signo(signo);

    if (c_hash_table_get(base->watchers, &key, (void **)&watcher) == 0) {
        watcher = io_watcher_new(IO_WATCHER_SIGNAL);

        watcher->events = IO_EVENT_SIGNAL_RECEIVED;
        watcher->key = key;
        watcher->cb_arg = arg;

        watcher->u.signal.signo = signo;
        watcher->u.signal.cb = cb;

        c_hash_table_insert(base->watchers, &watcher->key, watcher);
    }

    if (io_base_enable_signal_backend(base, watcher) == -1) {
        if (!watcher->registered) {
            c_hash_table_remove(base->watchers, &watcher->key);
            io_watcher_delete(watcher);
        }

        return -1;
    }

    watcher->registered = true;
    return 0;
}

int
io_base_unwatch_signal(struct io_base *base, int signo) {
    struct io_watcher *watcher;
    uint64_t key;

    key = io_watcher_key_signo(signo);

    if (c_hash_table_get(base->watchers, &key, (void **)&watcher) == 0) {
        c_set_error("no watcher found");
        return -1;
    }

    if (io_base_disable_signal_backend(base, watcher) == -1)
        return -1;

    c_hash_table_remove(base->watchers, &key);
    io_watcher_delete(watcher);
    return 0;
}

int
io_base_watch_fd(struct io_base *base, int fd, uint32_t events,
                 io_fd_callback cb, void *arg) {
    struct io_watcher *watcher;
    uint64_t key;

    key = io_watcher_key_fd(fd);

    if (c_hash_table_get(base->watchers, &key, (void **)&watcher) == 0) {
        watcher = io_watcher_new(IO_WATCHER_FD);

        watcher->events = events;
        watcher->key = key;
        watcher->cb_arg = arg;

        watcher->u.fd.fd = fd;
        watcher->u.fd.cb = cb;

        c_hash_table_insert(base->watchers, &watcher->key, watcher);
    }

    if (io_base_enable_fd_backend(base, watcher) == -1) {
        if (!watcher->registered) {
            c_hash_table_remove(base->watchers, &watcher->key);
            io_watcher_delete(watcher);
        }

        return -1;
    }

    watcher->registered = true;
    return 0;
}

int
io_base_unwatch_fd(struct io_base *base, int fd) {
    struct io_watcher *watcher;
    uint64_t key;

    key = io_watcher_key_fd(fd);

    if (c_hash_table_get(base->watchers, &key, (void **)&watcher) == 0) {
        c_set_error("no watcher found");
        return -1;
    }

    if (io_base_disable_fd_backend(base, watcher) == -1)
        return -1;

    c_hash_table_remove(base->watchers, &key);
    io_watcher_delete(watcher);
    return 0;
}

bool
io_base_has_watchers(const struct io_base *base) {
    return c_hash_table_nb_entries(base->watchers) > 0;
}

int
io_base_read_events(struct io_base *base) {
    if (io_base_read_events_backend(base) == -1)
        return -1;

    return 0;
}
