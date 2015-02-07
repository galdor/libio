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

#include <poll.h>

#include <signal.h>

#include "io.h"

static void ioex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

static void ioex_on_signal(int, void *);

int
main(int argc, char **argv) {
    struct io_base *base;
    struct pollfd pfd;

    base = io_base_new();

    if (io_base_watch_signal(base, SIGINT, ioex_on_signal, base) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());
    if (io_base_watch_signal(base, SIGTERM, ioex_on_signal, base) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());

    pfd.fd = io_base_fd(base);
    pfd.events = POLLIN;

    while (io_base_has_watchers(base)) {
        int ret;

        ret = poll(&pfd, 1, -1);
        if (ret == -1)
            ioex_die("cannot poll: %s", c_get_error());

        if (ret == 0)
            continue;

        printf("event available\n");

        if (io_base_read_events(base) == -1)
            ioex_die("cannot read events: %s", c_get_error());
    }

    io_base_delete(base);
    return 0;
}

void
ioex_die(const char *fmt, ...) {
    va_list ap;

    fprintf(stderr, "fatal error: ");

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    putc('\n', stderr);
    exit(1);
}

static void
ioex_on_signal(int signo, void *arg) {
    struct io_base *base;

    base = arg;

    printf("signal %d received", signo);

    switch (signo) {
    case SIGINT:
    case SIGTERM:
        io_base_unwatch_signal(base, SIGINT);
        io_base_unwatch_signal(base, SIGTERM);
        break;
    }
}
