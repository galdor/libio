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

    case IO_WATCHER_TIMER:
        if (watcher->u.timer.cb) {
            uint64_t now, duration;

            if (io_read_monotonic_clock_ms(&now) == -1) {
                duration = 0;
            } else {
                duration = now - watcher->u.timer.start_time;
            }

            watcher->u.timer.expired = true;
            watcher->u.timer.cb(duration, watcher->cb_arg);
        }
        break;
    }
}

/* ------------------------------------------------------------------------
 *  Watcher arrays
 * ------------------------------------------------------------------------ */
void
io_watcher_array_init(struct io_watcher_array *array) {
    memset(array, 0, sizeof(struct io_watcher_array));
}

void
io_watcher_array_free(struct io_watcher_array *array) {
    if (!array)
        return;

    for (size_t i = 0; i < array->size; i++)
        io_watcher_delete(array->watchers[i]);

    c_free(array->watchers);

    memset(array, 0, sizeof(struct io_watcher_array));
}

void
io_watcher_array_add(struct io_watcher_array *array, int id,
                     struct io_watcher *watcher) {
    size_t nsize;

    assert(id >= 0);
    assert((size_t)id < (SIZE_MAX / 3) * 2);

    if ((size_t)id >= array->size) {
        nsize = (array->size / 2) * 3;
        if ((size_t)id >= nsize)
            nsize = (size_t)id + 1;

        array->watchers = c_realloc(array->watchers,
                                    nsize * sizeof(struct io_watcher));
        memset(array->watchers + array->size, 0,
               (nsize - array->size) * sizeof(struct io_watcher *));

        array->size = nsize;
    }

    assert(!array->watchers[id]);

    array->watchers[id] = watcher;
    array->nb_watchers++;
}

void
io_watcher_array_remove(struct io_watcher_array *array, int id) {
    assert(id >= 0);
    assert((size_t)id < array->size);

    array->watchers[id] = NULL;
    array->nb_watchers--;

    if ((size_t)id == (array->size - 1) && array->size >= 9) {
        size_t last_unused, limit;

        last_unused = array->size - 1;
        while (last_unused > 0) {
            if (array->watchers[last_unused - 1])
                break;

            last_unused--;
        }

        limit = (array->size / 3) * 2;
        if (last_unused < limit) {
            array->watchers = c_realloc(array->watchers,
                                        limit * sizeof(struct io_watcher *));
            array->size = limit;
        }
    }
}

struct io_watcher *
io_watcher_array_get(const struct io_watcher_array *array, int id) {
    assert(id >= 0);

    if ((size_t)id >= array->size)
        return NULL;

    return array->watchers[id];
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

    io_watcher_array_init(&base->fd_watchers);
    io_watcher_array_init(&base->signal_watchers);
    io_watcher_array_init(&base->timer_watchers);

    return base;
}

void
io_base_delete(struct io_base *base) {
    if (!base)
        return;

    io_watcher_array_free(&base->fd_watchers);
    io_watcher_array_free(&base->signal_watchers);
    io_watcher_array_free(&base->timer_watchers);

    io_base_free_backend(base);

    c_free0(base, sizeof(struct io_base));
}

int
io_base_watch_fd(struct io_base *base, int fd, uint32_t events,
                 io_fd_callback cb, void *arg) {
    struct io_watcher *watcher;
    bool is_new;

    assert(fd >= 0);

    watcher = io_watcher_array_get(&base->fd_watchers, fd);
    if (!watcher) {
        is_new = true;

        watcher = io_watcher_new(IO_WATCHER_FD);

        watcher->events = events;
        watcher->cb_arg = arg;

        watcher->u.fd.fd = fd;
        watcher->u.fd.cb = cb;
    }

    if (io_base_enable_fd_backend(base, watcher) == -1) {
        if (is_new)
            io_watcher_delete(watcher);
        return -1;
    }

    watcher->registered = true;
    io_watcher_array_add(&base->fd_watchers, fd, watcher);
    return 0;
}

int
io_base_unwatch_fd(struct io_base *base, int fd) {
    struct io_watcher *watcher;

    assert(fd >= 0);

    watcher = io_watcher_array_get(&base->fd_watchers, fd);
    if (!watcher) {
        c_set_error("no watcher found");
        return -1;
    }

    if (io_base_disable_fd_backend(base, watcher) == -1)
        return -1;

    io_watcher_array_remove(&base->fd_watchers, fd);
    io_watcher_delete(watcher);
    return 0;
}

int
io_base_watch_signal(struct io_base *base, int signo,
                     io_signal_callback cb, void *arg) {
    struct io_watcher *watcher;
    bool is_new;

    assert(signo >= 0);

    watcher = io_watcher_array_get(&base->signal_watchers, signo);
    if (!watcher) {
        is_new = true;

        watcher = io_watcher_new(IO_WATCHER_SIGNAL);

        watcher->events = IO_EVENT_SIGNAL_RECEIVED;
        watcher->cb_arg = arg;

        watcher->u.signal.signo = signo;
        watcher->u.signal.cb = cb;
    }

    if (io_base_enable_signal_backend(base, watcher) == -1) {
        if (is_new)
            io_watcher_delete(watcher);
        return -1;
    }

    watcher->registered = true;
    io_watcher_array_add(&base->signal_watchers, signo, watcher);
    return 0;
}

int
io_base_unwatch_signal(struct io_base *base, int signo) {
    struct io_watcher *watcher;

    assert(signo >= 0);

    watcher = io_watcher_array_get(&base->signal_watchers, signo);
    if (!watcher) {
        c_set_error("no watcher found");
        return -1;
    }

    if (io_base_disable_signal_backend(base, watcher) == -1)
        return -1;

    io_watcher_array_remove(&base->signal_watchers, signo);
    io_watcher_delete(watcher);
    return 0;
}

int
io_base_add_timer(struct io_base *base, uint64_t duration, uint32_t flags,
                  io_timer_callback cb, void *arg) {
    struct io_watcher *watcher;
    uint64_t now;
    int id;

    if (io_read_monotonic_clock_ms(&now) == -1) {
        c_set_error("cannot read monotonic clock: %s", c_get_error());
        return -1;
    }

    id = ++base->last_timer_id;

    watcher = io_watcher_new(IO_WATCHER_TIMER);

    watcher->events = IO_EVENT_TIMER_EXPIRED;
    watcher->cb_arg = arg;

    watcher->u.timer.id = id;
    watcher->u.timer.duration = duration;
    watcher->u.timer.flags = flags;
    watcher->u.timer.start_time = now;
    watcher->u.timer.expiration_time = now + duration;
    watcher->u.timer.cb = cb;

    if (io_base_enable_timer_backend(base, watcher) == -1) {
        io_watcher_delete(watcher);
        return -1;
    }

    watcher->registered = true;
    io_watcher_array_add(&base->timer_watchers, id, watcher);
    return id;
}

int
io_base_remove_timer(struct io_base *base, int id) {
    struct io_watcher *watcher;

    watcher = io_watcher_array_get(&base->timer_watchers, id);
    if (!watcher) {
        c_set_error("no watcher found");
        return -1;
    }

    if (io_base_disable_timer_backend(base, watcher) == -1)
        return -1;

    io_watcher_array_remove(&base->timer_watchers, id);
    io_watcher_delete(watcher);
    return 0;
}

bool
io_base_has_watchers(const struct io_base *base) {
    return base->fd_watchers.nb_watchers > 0
        || base->signal_watchers.nb_watchers > 0
        || base->timer_watchers.nb_watchers > 0;
}

int
io_base_read_events(struct io_base *base) {
    if (io_base_read_events_backend(base) == -1)
        return -1;

    return 0;
}
