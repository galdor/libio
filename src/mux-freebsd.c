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

#ifdef IO_PLATFORM_FREEBSD

#include <sys/time.h>
#include <sys/types.h>
#include <sys/event.h>

#include "internal.h"

/* ------------------------------------------------------------------------
 *  Watcher
 * ------------------------------------------------------------------------ */
void
io_watcher_free_backend(struct io_watcher *watcher) {
    switch (watcher->type) {
    case IO_WATCHER_FD:
    case IO_WATCHER_SIGNAL:
    case IO_WATCHER_TIMER:
    case IO_WATCHER_CHILD:
        break;
    }
}

/* ------------------------------------------------------------------------
 *  Base
 * ------------------------------------------------------------------------ */
int
io_base_init_backend(struct io_base *base) {
    base->fd = kqueue();
    if (base->fd == -1) {
        c_set_error("cannot create kqueue: %s", strerror(errno));
        return -1;
    }

    return 0;
}

void
io_base_free_backend(struct io_base *base) {
    if (base->fd >= 0) {
        close(base->fd);
        base->fd = -1;
    }
}

int
io_base_enable_fd_backend(struct io_base *base, struct io_watcher *watcher) {
    struct kevent events[2];
    size_t nb_events;

    assert(watcher->type == IO_WATCHER_FD);

    memset(events, 0, sizeof(events));

    nb_events = 0;

    if (watcher->events & IO_EVENT_FD_READ
     || watcher->events & IO_EVENT_FD_HANGUP) {
        events[nb_events].ident = (uintptr_t)watcher->u.signal.signo;
        events[nb_events].filter = EVFILT_READ;
        events[nb_events].flags = EV_ADD;
        events[nb_events].udata = watcher;
        nb_events++;
    }

    if (watcher->events & IO_EVENT_FD_WRITE) {
        events[nb_events].ident = (uintptr_t)watcher->u.signal.signo;
        events[nb_events].filter = EVFILT_READ;
        events[nb_events].flags = EV_ADD;
        events[nb_events].udata = watcher;
        nb_events++;
    }

    if (kevent(base->fd, events, nb_events, NULL, 0, NULL) == -1) {
        c_set_error("cannot add fd filter to kqueue: %s",
                    strerror(errno));
        return -1;
    }

    return 0;
}

int
io_base_disable_fd_backend(struct io_base *base, struct io_watcher *watcher) {
    struct kevent events[2];
    size_t nb_events;

    assert(watcher->type == IO_WATCHER_FD);

    memset(events, 0, sizeof(events));

    nb_events = 0;

    if (watcher->events & IO_EVENT_FD_READ
     || watcher->events & IO_EVENT_FD_HANGUP) {
        events[nb_events].ident = (uintptr_t)watcher->u.signal.signo;
        events[nb_events].filter = EVFILT_READ;
        events[nb_events].flags = EV_DELETE;
        nb_events++;
    }

    if (watcher->events & IO_EVENT_FD_WRITE) {
        events[nb_events].ident = (uintptr_t)watcher->u.signal.signo;
        events[nb_events].filter = EVFILT_READ;
        events[nb_events].flags = EV_DELETE;
        nb_events++;
    }

    if (kevent(base->fd, events, nb_events, NULL, 0, NULL) == -1) {
        c_set_error("cannot remove fd filter from kqueue: %s",
                    strerror(errno));
        return -1;
    }

    return 0;
}

int
io_base_enable_signal_backend(struct io_base *base,
                              struct io_watcher *watcher) {
    struct kevent event;
    struct sigaction sa;
    int signo;

    assert(watcher->type == IO_WATCHER_SIGNAL);

    signo = watcher->u.signal.signo;

    memset(&event, 0, sizeof(struct kevent));
    event.ident = (uintptr_t)watcher->u.signal.signo;
    event.filter = EVFILT_SIGNAL;
    event.flags = EV_ADD;
    event.udata = watcher;

    /* Ignoring SIGCHLD makes the kernel automatically collect zombie
     * processes without notifying us. */
    if (!watcher->registered && signo != SIGCHLD) {
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_handler = SIG_IGN;

        if (sigaction(signo, &sa, NULL) == -1) {
            c_set_error("cannot ignore signal: %s", strerror(errno));
            return -1;
        }
    }

    if (kevent(base->fd, &event, 1, NULL, 0, NULL) == -1) {
        c_set_error("cannot add signal filter to kqueue: %s", strerror(errno));

        if (!watcher->registered && signo != SIGCHLD) {
            memset(&sa, 0, sizeof(struct sigaction));
            sa.sa_handler = SIG_DFL;

            sigaction(watcher->u.signal.signo, &sa, NULL);
        }
        return -1;
    }

    return 0;
}

int
io_base_disable_signal_backend(struct io_base *base,
                               struct io_watcher *watcher) {
    struct kevent event;
    struct sigaction sa;
    int signo;

    assert(watcher->type == IO_WATCHER_SIGNAL);

    signo = watcher->u.signal.signo;

    memset(&event, 0, sizeof(struct kevent));
    event.ident = (uintptr_t)watcher->u.signal.signo;
    event.filter = EVFILT_SIGNAL;
    event.flags = EV_DELETE;

    if (kevent(base->fd, &event, 1, NULL, 0, NULL) == -1) {
        c_set_error("cannot remove signal filter from kqueue: %s",
                    strerror(errno));
        return -1;
    }

    /* Restore the default signal handler */
    if (signo != SIGCHLD) {
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_handler = SIG_DFL;

        sigaction(watcher->u.signal.signo, &sa, NULL);
    }

    return 0;
}

int
io_base_enable_timer_backend(struct io_base *base,
                             struct io_watcher *watcher) {
    struct kevent event;

    assert(watcher->type == IO_WATCHER_TIMER);

    memset(&event, 0, sizeof(struct kevent));
    event.ident = (uintptr_t)watcher->u.timer.id;
    event.filter = EVFILT_TIMER;
    event.flags = EV_ADD;
    if (!(watcher->u.timer.flags & IO_TIMER_RECURRENT))
        event.flags |= EV_ONESHOT;
    event.data = (intptr_t)watcher->u.timer.duration;
    event.udata = watcher;

    if (kevent(base->fd, &event, 1, NULL, 0, NULL) == -1) {
        c_set_error("cannot add timer filter to kqueue: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int
io_base_disable_timer_backend(struct io_base *base,
                              struct io_watcher *watcher) {
    struct kevent event;

    assert(watcher->type == IO_WATCHER_TIMER);

    if (!(watcher->u.timer.flags & IO_TIMER_RECURRENT)
     && watcher->u.timer.expired) {
        /* Oneshot timers are automatically deleted from the kqueue once they
         * have expired. */
        return 0;
    }

    memset(&event, 0, sizeof(struct kevent));
    event.ident = (uintptr_t)watcher->u.timer.id;
    event.filter = EVFILT_TIMER;
    event.flags = EV_DELETE;

    if (kevent(base->fd, &event, 1, NULL, 0, NULL) == -1) {
        c_set_error("cannot remove timer filter from kqueue: %s",
                    strerror(errno));
        return -1;
    }

    return 0;
}

int
io_base_update_timer_backend(struct io_base *base, struct io_watcher *watcher) {
    struct kevent event[2];

    assert(watcher->type == IO_WATCHER_TIMER);

    memset(&event, 0, sizeof(event));

    event[0].ident = (uintptr_t)watcher->u.timer.id;
    event[0].filter = EVFILT_TIMER;
    event[0].flags = EV_DELETE;

    event[1].ident = (uintptr_t)watcher->u.timer.id;
    event[1].filter = EVFILT_TIMER;
    event[1].flags = EV_ADD;
    if (!(watcher->u.timer.flags & IO_TIMER_RECURRENT))
        event[1].flags |= EV_ONESHOT;
    event[1].data = (intptr_t)watcher->u.timer.duration;
    event[1].udata = watcher;

    if (kevent(base->fd, event, 2, NULL, 0, NULL) == -1) {
        c_set_error("cannot update timer filter in kqueue: %s",
                    strerror(errno));
        return -1;
    }

    return 0;
}

int
io_base_read_events_backend(struct io_base *base) {
    struct io_watcher *watcher;
    struct kevent event;
    uint32_t events;
    int ret;

    ret = kevent(base->fd, NULL, 0, &event, 1, NULL);
    if (ret == -1) {
        if (errno == EINTR) {
            return 0;
        } else {
            c_set_error("cannot poll events: %s", strerror(errno));
            return -1;
        }
        return -1;
    }

    if (ret == 0)
        return 0;

    watcher = event.udata;

    events = 0;

    switch (watcher->type) {
    case IO_WATCHER_FD:
        if (event.filter == EVFILT_READ) {
            events |= IO_EVENT_FD_READ;

            if (event.flags & EV_EOF)
                events |= IO_EVENT_FD_HANGUP;
        } else if (event.filter == EVFILT_WRITE) {
            events |= IO_EVENT_FD_WRITE;
        }
        break;

    case IO_WATCHER_SIGNAL:
        if (event.filter == EVFILT_SIGNAL)
            events |= IO_EVENT_SIGNAL_RECEIVED;
        break;

    case IO_WATCHER_TIMER:
        if (event.filter == EVFILT_TIMER)
            events |= IO_EVENT_TIMER_EXPIRED;
        break;

    case IO_WATCHER_CHILD:
        break;
    }

    if (events == 0)
        return 0;

    io_watcher_on_events(watcher, events);
    return 0;
}

#endif
