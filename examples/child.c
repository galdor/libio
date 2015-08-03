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
#include <string.h>

#include <unistd.h>

#include "io.h"

struct ioex {
    struct io_base *base;
    bool do_exit;

    pid_t pid;
};

static void ioex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

static void ioex_on_signal(int, void *);
static void ioex_on_child_event(pid_t, uint32_t, int, void *);

struct ioex ioex;

int
main(int argc, char **argv) {
    struct c_command_line *cmdline;
    const char *program;

    cmdline = c_command_line_new();

    c_command_line_add_argument(cmdline, "the command to execute", "command");

    if (c_command_line_parse(cmdline, argc, argv) == -1)
        ioex_die("%s", c_get_error());

    program = c_command_line_argument_value(cmdline, 0);

    ioex.base = io_base_new();

    if (io_base_watch_signal(ioex.base, SIGINT, ioex_on_signal, NULL) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());
    if (io_base_watch_signal(ioex.base, SIGTERM, ioex_on_signal, NULL) == -1)
        ioex_die("cannot watch signal: %s", c_get_error());
    if (io_base_watch_sigchld(ioex.base) == -1)
        ioex_die("cannot watch sigchld: %s", c_get_error());

    ioex.pid = fork();
    if (ioex.pid == -1)
        ioex_die("cannot fork: %s", strerror(errno));

    if (ioex.pid == 0) {
        /* Child */
        if (execlp(program, program, NULL) == -1)
            exit(1);
    } else {
        /* Parent */
        if (io_base_watch_child(ioex.base, ioex.pid,
                                ioex_on_child_event, NULL) == -1) {
            ioex_die("cannot watch child: %s", c_get_error());
        }
    }

    while (!ioex.do_exit) {
        if (io_base_read_events(ioex.base) == -1)
            ioex_die("cannot read events: %s", c_get_error());
    }

    io_base_unwatch_signal(ioex.base, SIGINT);
    io_base_unwatch_signal(ioex.base, SIGTERM);

    if (ioex.pid > 1) {
        if (kill(ioex.pid, SIGTERM) == -1)
            ioex_die("cannot kill child %d: %s", ioex.pid, strerror(errno));
    }

    while (io_base_has_watchers(ioex.base)) {
        if (io_base_read_events(ioex.base) == -1)
            ioex_die("cannot read events: %s", c_get_error());
    }

    io_base_delete(ioex.base);

    c_command_line_delete(cmdline);
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
ioex_on_child_event(pid_t pid, uint32_t event, int value, void *arg) {
    switch (event) {
    case IO_EVENT_CHILD_EXITED:
        printf("child %d exited with code %d\n", pid, value);
        break;

    case IO_EVENT_CHILD_SIGNALED:
        printf("child %d killed by signal %d\n", pid, value);
        break;

    case IO_EVENT_CHILD_ABORTED:
        printf("child %d aborted\n", pid);
        break;
    }

    ioex.pid = (pid_t)-1;
    ioex.do_exit = true;

    io_base_unwatch_sigchld(ioex.base);
}
