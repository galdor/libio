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

#include <fcntl.h>
#include <unistd.h>

#include "internal.h"

static int io_fd_add_remove_flags(int, int, int, int, int);

int
io_fd_set_blocking(int fd) {
    return io_fd_add_remove_flags(fd, F_GETFL, F_SETFL, 0, O_NONBLOCK);
}

int
io_fd_set_non_blocking(int fd) {
    return io_fd_add_remove_flags(fd, F_GETFL, F_SETFL, O_NONBLOCK, 0);
}

int
io_fd_set_cloexec(int fd) {
    return io_fd_add_remove_flags(fd, F_GETFD, F_SETFD, FD_CLOEXEC, 0);
}

static int
io_fd_add_remove_flags(int fd, int getval, int setval,
                       int added_flags, int removed_flags) {
    int current_flags;

    current_flags = fcntl(fd, getval, 0);
    if (current_flags == -1) {
        c_set_error("cannot get file descriptor flags: %s", strerror(errno));
        return -1;
    }

    current_flags |= added_flags;
    current_flags &= ~removed_flags;

    if (fcntl(fd, setval, current_flags) == -1) {
        c_set_error("cannot set file descriptor flags: %s", strerror(errno));
        return -1;
    }

    return 0;
}
