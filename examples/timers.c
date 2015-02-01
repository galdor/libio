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
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "io.h"

struct ioex {
    struct io_base *base;
    bool do_exit;

    int64_t timer1;
    int64_t timer2;
};

static void ioex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

static void ioex_on_timer1(uint64_t, void *);
static void ioex_on_timer2(uint64_t, void *);

static struct ioex ioex;

int
main(int argc, char **argv) {
    ioex.base = io_base_new();

    ioex.timer1 = io_base_add_timer(ioex.base, 1000, IO_TIMER_RECURRENT,
                                    ioex_on_timer1, NULL);
    if (!ioex.timer1)
        ioex_die("cannot add timer: %s", c_get_error());

    ioex.timer2 = io_base_add_timer(ioex.base, 5000, 0, ioex_on_timer2, NULL);
    if (!ioex.timer2)
        ioex_die("cannot add timer: %s", c_get_error());

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
ioex_on_timer1(uint64_t duration, void *arg) {
    static uint32_t count = 0;

    printf("timer1: %"PRIu64"ms\n", duration);

    if (++count >= 3)
        io_base_remove_timer(ioex.base, ioex.timer1);
}

static void
ioex_on_timer2(uint64_t duration, void *arg) {
    printf("timer2: %"PRIu64"ms\n", duration);
    io_base_remove_timer(ioex.base, ioex.timer2);
}
