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

#ifdef IO_PLATFORM_LINUX

#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "internal.h"

/* ------------------------------------------------------------------------
 *  Watcher
 * ------------------------------------------------------------------------ */
void
io_watcher_free_backend(struct io_watcher *watcher) {
    switch (watcher->type) {
    case IO_WATCHER_FD:
        break;

    case IO_WATCHER_SIGNAL:
        if (watcher->u.signal.fd >= 0)
            close(watcher->u.signal.fd);
        break;
    }
}

/* ------------------------------------------------------------------------
 *  Base
 * ------------------------------------------------------------------------ */
int
io_base_init_backend(struct io_base *base) {
    base->fd = epoll_create(32);
    if (base->fd == -1) {
        c_set_error("cannot create epoll instance: %s", strerror(errno));
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
io_base_enable_watcher_signal_backend(struct io_base *base,
                                      struct io_watcher *watcher) {
    struct epoll_event event;
    sigset_t mask;
    int fd;

    assert(watcher->type == IO_WATCHER_SIGNAL);

    fd = watcher->u.signal.fd;

    memset(&event, 0, sizeof(struct epoll_event));
    event.events = EPOLLIN;
    event.data.ptr = watcher;

    if (fd >= 0) {
        if (epoll_ctl(base->fd, EPOLL_CTL_MOD, fd, &event) == -1) {
            c_set_error("cannot update signal fd in epoll instance: %s",
                        strerror(errno));
            return -1;
        }

        return 0;
    }

    sigemptyset(&mask);
    sigaddset(&mask, watcher->u.signal.signo);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        c_set_error("cannot block signal: %s", strerror(errno));
        return -1;
    }

    fd = signalfd(-1, &mask, SFD_NONBLOCK);
    if (fd == -1) {
        c_set_error("cannot create signal fd: %s", strerror(errno));
        sigprocmask(SIG_UNBLOCK, &mask, NULL);
        return -1;
    }

    if (epoll_ctl(base->fd, EPOLL_CTL_ADD, fd, &event) == -1) {
        c_set_error("cannot add signal fd to epoll instance: %s",
                    strerror(errno));
        sigprocmask(SIG_UNBLOCK, &mask, NULL);
        close(fd);
        return -1;
    }

    watcher->u.signal.fd = fd;
    return 0;
}

int
io_base_disable_watcher_signal_backend(struct io_base *base,
                                       struct io_watcher *watcher) {
    sigset_t mask;

    assert(watcher->type == IO_WATCHER_SIGNAL);

    if (epoll_ctl(base->fd, EPOLL_CTL_DEL, watcher->u.signal.fd, NULL) == -1) {
        c_set_error("cannot remove signal fd from epoll instance: %s",
                    c_get_error());
        return -1;
    }

    close(watcher->u.signal.fd);

    /* Restore the old signal handler */
    sigemptyset(&mask);
    sigaddset(&mask, watcher->u.signal.signo);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    watcher->u.signal.fd = -1;
    return 0;
}

int
io_base_read_events_backend(struct io_base *base) {
    struct io_watcher *watcher;
    struct epoll_event event;
    uint32_t events;
    int ret;

    ret = epoll_wait(base->fd, &event, 1, -1);
    if (ret == -1) {
        if (errno == EINTR) {
            return 0;
        } else {
            c_set_error("cannot poll events: %s", strerror(errno));
            return -1;
        }
    }

    if (ret == 0)
        return 0;

    watcher = event.data.ptr;

    events = 0;

    switch (watcher->type) {
    case IO_WATCHER_FD:
        if (event.events & EPOLLIN)
            events |= IO_EVENT_FD_READ;
        if (event.events & EPOLLOUT)
            events |= IO_EVENT_FD_WRITE;
        if (event.events & EPOLLHUP)
            events |= IO_EVENT_FD_HANGHUP;
        if (event.events & EPOLLERR)
            events |= IO_EVENT_FD_ERROR;
        break;

    case IO_WATCHER_SIGNAL:
        if (event.events & EPOLLIN) {
            struct signalfd_siginfo info;
            ssize_t ret;

            ret = read(watcher->u.signal.fd, &info, sizeof(info));
            if (ret == -1) {
                c_set_error("cannot read signal fd: %s", strerror(errno));
                return -1;
            } else if ((size_t)ret < sizeof(info)) {
                c_set_error("read truncated data on signal fd");
                return -1;
            }

            events |= IO_EVENT_SIGNAL_RECEIVED;
        }
        break;
    }

    if (events == 0)
        return 0;

    io_watcher_on_events(watcher, events);
    return 0;
}

#endif
