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

#include <limits.h>

#include <sys/wait.h>

#include "internal.h"

/* ------------------------------------------------------------------------
 *  Watcher
 * ------------------------------------------------------------------------ */
struct io_watcher *
io_watcher_new(struct io_base *base, enum io_watcher_type type) {
    struct io_watcher *watcher;

    watcher = c_malloc0(sizeof(struct io_watcher));

    watcher->base = base;
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
    struct io_watcher_array *array;
    bool is_recurrent;
    int id;

    switch (watcher->type) {
    case IO_WATCHER_FD:
        array = &watcher->base->fd_watchers;
        id = watcher->u.fd.fd;

        watcher->in_cb = true;
        if (watcher->u.fd.cb)
            watcher->u.fd.cb(watcher->u.fd.fd, events, watcher->cb_arg);
        watcher->in_cb = false;
        break;

    case IO_WATCHER_SIGNAL:
        array = &watcher->base->signal_watchers;
        id = watcher->u.signal.signo;

        watcher->in_cb = true;
        if (watcher->u.signal.cb)
            watcher->u.signal.cb(watcher->u.signal.signo, watcher->cb_arg);
        watcher->in_cb = false;
        break;

    case IO_WATCHER_TIMER:
        array = &watcher->base->timer_watchers;
        id = watcher->u.timer.id;

        is_recurrent = (watcher->u.timer.flags & IO_TIMER_RECURRENT);

        if (watcher->u.timer.cb) {
            uint64_t now, duration;

            if (io_read_monotonic_clock_ms(&now) == -1) {
                duration = 0;
            } else {
                duration = now - watcher->u.timer.start_time;
            }

            watcher->u.timer.expired = true;

            watcher->in_cb = true;
            watcher->u.timer.cb(id, duration, watcher->cb_arg);
            watcher->in_cb = false;
        }

        if (watcher->enabled && is_recurrent) {
            if (io_read_monotonic_clock_ms(&watcher->u.timer.start_time) == -1) {
                /* TODO signal error */
            }
        }
        break;

    case IO_WATCHER_CHILD:
        watcher->in_cb = true;
        if (watcher->u.child.cb) {
            watcher->u.child.cb(watcher->u.child.pid, events,
                                watcher->u.child.event_value, watcher->cb_arg);
        }
        watcher->in_cb = false;
        break;
    }

    if (!watcher->enabled) {
        /* The watcher was disabled in the callback */
        if (watcher->type == IO_WATCHER_CHILD) {
            c_hash_table_remove(watcher->base->child_watchers,
                                &watcher->u.child.pid);
        } else {
            io_watcher_array_remove(array, id);
        }

        if (watcher->type == IO_WATCHER_TIMER)
            io_base_release_timer_id(watcher->base, id);

        io_watcher_delete(watcher);
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

bool
io_watcher_array_contains(const struct io_watcher_array *array, int id) {
    assert(id >= 0);

    return ((size_t)id < array->size) && (array->watchers[id] != NULL);
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
static void io_base_on_sigchld(int, void *);
static int io_cmp_timer_ids(const void *, const void *);

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
    base->child_watchers = c_hash_table_new(io_hash_pid_ptr, io_equal_pid_ptr);

    base->free_timer_ids = c_heap_new(io_cmp_timer_ids);

    return base;
}

void
io_base_delete(struct io_base *base) {
    struct c_hash_table_iterator *it;
    struct io_watcher *watcher;

    if (!base)
        return;

    io_watcher_array_free(&base->fd_watchers);
    io_watcher_array_free(&base->signal_watchers);
    io_watcher_array_free(&base->timer_watchers);

    it = c_hash_table_iterate(base->child_watchers);
    while (c_hash_table_iterator_next(it, NULL, (void **)&watcher) == 1)
        io_watcher_delete(watcher);
    c_hash_table_iterator_delete(it);
    c_hash_table_delete(base->child_watchers);

    c_heap_delete(base->free_timer_ids);

    io_base_free_backend(base);

    c_free0(base, sizeof(struct io_base));
}

int
io_base_fd(const struct io_base *base) {
    return base->fd;
}

int
io_base_watch_fd(struct io_base *base, int fd, uint32_t events,
                 io_fd_cb cb, void *arg) {
    struct io_watcher *watcher;
    bool is_new;
    uint32_t old_events;
    io_fd_cb old_cb;
    void *old_cb_arg;

    assert(fd >= 0);

    watcher = io_watcher_array_get(&base->fd_watchers, fd);

    if (watcher) {
        is_new = false;

        if (watcher->enabled
         && watcher->events == events
         && watcher->cb_arg == arg
         && watcher->u.fd.cb == cb) {
            return 0;
        }

        old_events = watcher->events;
        old_cb_arg = watcher->cb_arg;
        old_cb = watcher->u.fd.cb;

        watcher->events = events;
        watcher->cb_arg = arg;
        watcher->u.fd.cb = cb;
    } else {
        is_new = true;

        watcher = io_watcher_new(base, IO_WATCHER_FD);

        watcher->events = events;
        watcher->cb_arg = arg;

        watcher->u.fd.fd = fd;
        watcher->u.fd.cb = cb;
    }

    if (io_base_enable_fd_backend(base, watcher) == -1) {
        if (is_new)
            io_watcher_delete(watcher);

        watcher->events = old_events;
        watcher->cb_arg = old_cb_arg;
        watcher->u.fd.cb = old_cb;
        return -1;
    }

    if (is_new)
        io_watcher_array_add(&base->fd_watchers, fd, watcher);

    watcher->registered = true;
    watcher->enabled = true;
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

    watcher->registered = false;
    watcher->enabled = false;
    if (!watcher->in_cb) {
        io_watcher_array_remove(&base->fd_watchers, fd);
        io_watcher_delete(watcher);
    }
    return 0;
}

bool
io_base_is_fd_watched(const struct io_base *base, int fd) {
    return io_watcher_array_contains(&base->fd_watchers, fd);
}

int
io_base_watch_signal(struct io_base *base, int signo,
                     io_signal_cb cb, void *arg) {
    struct io_watcher *watcher;

    assert(signo >= 0);

    watcher = io_watcher_array_get(&base->signal_watchers, signo);
    if (watcher) {
        watcher->cb_arg = arg;
        watcher->u.signal.cb = cb;
        return 0;
    }

    watcher = io_watcher_new(base, IO_WATCHER_SIGNAL);

    watcher->events = IO_EVENT_SIGNAL_RECEIVED;
    watcher->cb_arg = arg;

    watcher->u.signal.signo = signo;
    watcher->u.signal.cb = cb;

    if (io_base_enable_signal_backend(base, watcher) == -1) {
        io_watcher_delete(watcher);
        return -1;
    }

    watcher->registered = true;
    watcher->enabled = true;

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

    watcher->registered = false;
    watcher->enabled = false;
    if (!watcher->in_cb) {
        io_watcher_array_remove(&base->signal_watchers, signo);
        io_watcher_delete(watcher);
    }
    return 0;
}

bool
io_base_is_signal_watched(const struct io_base *base, int signo) {
    return io_watcher_array_contains(&base->signal_watchers, signo);
}

int
io_base_watch_sigchld(struct io_base *base) {
    return io_base_watch_signal(base, SIGCHLD, io_base_on_sigchld, base);
}

int
io_base_unwatch_sigchld(struct io_base *base) {
    return io_base_unwatch_signal(base, SIGCHLD);
}

int
io_base_add_timer(struct io_base *base, uint64_t duration, uint32_t flags,
                  io_timer_cb cb, void *arg) {
    struct io_watcher *watcher;
    uint64_t now;
    int id;

    if (io_read_monotonic_clock_ms(&now) == -1) {
        c_set_error("cannot read monotonic clock: %s", c_get_error());
        return -1;
    }

    id = io_base_generate_timer_id(base);
    if (id == -1)
        return -1;

    watcher = io_watcher_new(base, IO_WATCHER_TIMER);

    watcher->events = IO_EVENT_TIMER_EXPIRED;
    watcher->cb_arg = arg;

    watcher->u.timer.id = id;
    watcher->u.timer.duration = duration;
    watcher->u.timer.flags = flags;
    watcher->u.timer.start_time = now;
    watcher->u.timer.cb = cb;

    if (io_base_enable_timer_backend(base, watcher) == -1) {
        io_base_release_timer_id(base, id);

        io_watcher_delete(watcher);
        return -1;
    }

    watcher->registered = true;
    watcher->enabled = true;

    io_watcher_array_add(&base->timer_watchers, id, watcher);
    return id;
}

int
io_base_remove_timer(struct io_base *base, int id) {
    struct io_watcher *watcher;

    watcher = io_watcher_array_get(&base->timer_watchers, id);
    if (!watcher) {
        c_set_error("unknown timer");
        return -1;
    }

    if (io_base_disable_timer_backend(base, watcher) == -1)
        return -1;

    watcher->registered = false;
    watcher->enabled = false;
    if (!watcher->in_cb) {
        io_watcher_array_remove(&base->timer_watchers, id);
        io_base_release_timer_id(base, id);

        io_watcher_delete(watcher);
    }
    return 0;
}

int
io_base_update_timer(struct io_base *base, int id, uint64_t duration) {
    struct io_watcher *watcher;
    uint64_t old_duration;

    watcher = io_watcher_array_get(&base->timer_watchers, id);
    if (!watcher) {
        c_set_error("unknown timer");
        return -1;
    }

    old_duration = watcher->u.timer.duration;
    watcher->u.timer.duration = duration;

    if (io_base_update_timer_backend(base, watcher) == -1) {
        watcher->u.timer.duration = old_duration;
        return -1;
    }

    return 0;
}

int
io_base_watch_child(struct io_base *base, pid_t pid,
                    io_child_cb cb, void *cb_arg) {
    struct io_watcher *watcher;

    assert(pid != (pid_t)-1);

    if (c_hash_table_get(base->child_watchers, &pid, (void **)&watcher) == 1) {
        watcher->u.child.cb = cb;
        watcher->cb_arg = cb_arg;

        return 0;
    }

    watcher = io_watcher_new(base, IO_WATCHER_CHILD);

    watcher->events = IO_EVENT_CHILD_EXITED | IO_EVENT_CHILD_SIGNALED
                    | IO_EVENT_CHILD_ABORTED;
    watcher->cb_arg = cb_arg;

    watcher->u.child.pid = pid;
    watcher->u.child.cb = cb;

    watcher->registered = true;
    watcher->enabled = true;

    c_hash_table_insert(base->child_watchers, &watcher->u.child.pid, watcher);
    return 0;
}

int
io_base_unwatch_child(struct io_base *base, pid_t pid) {
    struct io_watcher *watcher;

    assert(pid != (pid_t)-1);

    if (c_hash_table_get(base->child_watchers, &pid, (void **)&watcher) == 0) {
        c_set_error("no watcher found");
        return -1;
    }

    watcher->registered = false;
    watcher->enabled = false;
    if (!watcher->in_cb) {
        c_hash_table_remove(base->child_watchers, &pid);
        io_watcher_delete(watcher);
    }

    return 0;
}

bool
io_base_is_child_watched(const struct io_base *base, pid_t pid) {
    return c_hash_table_contains(base->child_watchers, &pid);
}

bool
io_base_has_watchers(const struct io_base *base) {
    bool has_fd_watcher, has_signal_watcher, has_timer_watcher;
    bool has_child_watcher;

    has_fd_watcher = (base->fd_watchers.nb_watchers > 0);
    has_signal_watcher = (base->signal_watchers.nb_watchers > 0);
    has_timer_watcher = (base->timer_watchers.nb_watchers > 0);
    has_child_watcher = (c_hash_table_nb_entries(base->child_watchers) > 0);

    return has_fd_watcher || has_signal_watcher || has_timer_watcher
        || has_child_watcher;
}

size_t
io_base_nb_watchers(const struct io_base *base) {
    size_t count;

    count = 0;

    count += base->fd_watchers.nb_watchers;
    count += base->signal_watchers.nb_watchers;
    count += base->timer_watchers.nb_watchers;
    count += c_hash_table_nb_entries(base->child_watchers);

    return count;
}

void
io_base_print_watchers(const struct io_base *base, FILE *file) {
    struct c_hash_table_iterator *it;
    const struct io_watcher *watcher;

    fprintf(file, "libio watchers:\n");

    for (size_t i = 0; i < base->fd_watchers.size; i++) {
        watcher = base->fd_watchers.watchers[i];
        if (!watcher)
            continue;

        fprintf(file, "  %-8s  %5d\n", "fd", watcher->u.fd.fd);
    }

    for (size_t i = 0; i < base->signal_watchers.size; i++) {
        watcher = base->signal_watchers.watchers[i];
        if (!watcher)
            continue;

        fprintf(file, "  %-8s  %5d\n", "signal", watcher->u.signal.signo);
    }

    for (size_t i = 0; i < base->timer_watchers.size; i++) {
        watcher = base->timer_watchers.watchers[i];
        if (!watcher)
            continue;

        fprintf(file, "  %-8s  %5d\n", "timer", watcher->u.timer.id);
    }

    it = c_hash_table_iterate(base->child_watchers);
    while (c_hash_table_iterator_next(it, NULL, (void **)&watcher) == 1) {
        fprintf(file, "  %-8s  %5d\n", "child", watcher->u.child.pid);
    }
    c_hash_table_iterator_delete(it);
}

int
io_base_read_events(struct io_base *base) {
    if (io_base_read_events_backend(base) == -1)
        return -1;

    return 0;
}

int
io_base_generate_timer_id(struct io_base *base) {
    if (c_heap_is_empty(base->free_timer_ids)) {
        if (base->last_timer_id == INT_MAX) {
            c_set_error("too many timers");
            return -1;
        }

        return ++base->last_timer_id;
    }

    return C_POINTER_TO_INT32(c_heap_pop(base->free_timer_ids));
}

void
io_base_release_timer_id(struct io_base *base, int id) {
    assert(id > 0);

    if (id == base->last_timer_id) {
        base->last_timer_id--;
    } else {
        c_heap_add(base->free_timer_ids, C_INT32_TO_POINTER(id));
    }
}

static void
io_base_on_sigchld(int signo, void *arg) {
    struct io_base *base;

    assert(signo == SIGCHLD);

    base = arg;

    for (;;) {
        struct io_watcher *watcher;
        int status, event_value;
        enum io_event event;
        pid_t pid;

        pid = waitpid((pid_t)-1, &status, WNOHANG);
        if (pid == -1) {
            if (errno == ECHILD)
                break;

            /* TODO signal error */
            return;
        } else if (pid == 0) {
            return;
        }

        if (c_hash_table_get(base->child_watchers, &pid,
                             (void **)&watcher) == 0) {
            continue;
        }

        if (WIFEXITED(status)) {
            event = IO_EVENT_CHILD_EXITED;
            event_value = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            event = IO_EVENT_CHILD_SIGNALED;
            event_value = WTERMSIG(status);
        } else {
            event = IO_EVENT_CHILD_ABORTED;
            event_value = 0;
        }

        watcher->u.child.event_value = event_value;

        io_watcher_on_events(watcher, event);

        if (io_base_unwatch_child(base, pid) == -1) {
            /* TODO signal error */
        }
    }
}

static int
io_cmp_timer_ids(const void *e1, const void *e2) {
    int id1, id2;

    id1 = C_POINTER_TO_INT32(e1);
    id2 = C_POINTER_TO_INT32(e2);

    if (id1 < id2) {
        return -1;
    } else if (id1 > id2) {
        return 1;
    } else {
        return 0;
    }
}
