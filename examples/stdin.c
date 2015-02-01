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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include "io.h"

struct ioex {
    struct io_base *base;
    bool do_exit;
};

static void ioex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

static void ioex_on_signal(int, void *);
static void ioex_on_stdin_event(int, uint32_t, void *);

static struct ioex ioex;

int
main(int argc, char **argv) {
    uint32_t events;
    int fd;

    ioex.base = io_base_new();

    if (io_base_watch_signal(ioex.base, SIGINT, ioex_on_signal, NULL) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());
    if (io_base_watch_signal(ioex.base, SIGTERM, ioex_on_signal, NULL) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());

    fd = STDIN_FILENO;
    events = IO_EVENT_FD_READ | IO_EVENT_FD_HANGUP;

    if (io_base_watch_fd(ioex.base, fd, events,
                         ioex_on_stdin_event, NULL) == -1) {
        ioex_die("cannot watch stdin: %s", c_get_error());
    }

    while (!ioex.do_exit && io_base_has_watchers(ioex.base)) {
        if (io_base_read_events(ioex.base) == -1)
            ioex_die("cannot read events: %s", c_get_error());
    }

    io_base_delete(ioex.base);
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
    printf("signal %d received\n", signo);

    switch (signo) {
    case SIGINT:
    case SIGTERM:
        ioex.do_exit = true;
        break;
    }
}

static void
ioex_on_stdin_event(int fd, uint32_t events, void *arg) {
    if (events & IO_EVENT_FD_READ) {
        ssize_t ret;
        char buf[BUFSIZ];

        ret = read(STDIN_FILENO, buf, BUFSIZ);
        if (ret == -1)
            ioex_die("cannot read stdin: %s", strerror(errno));

        printf("%zi bytes read on stdin\n", ret);
    }

    if (events & IO_EVENT_FD_HANGUP) {
        printf("stdin hanged up\n");
        ioex.do_exit = true;
    }
}
