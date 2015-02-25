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

#include "internal.h"

uint32_t
io_hash_uint64_ptr(const void *key) {
    const uint8_t *bytes;
    uint32_t hash;

    bytes = key;

    hash = 5381;
    for (size_t i = 0; i < 8; i++)
        hash = ((hash << 5) + hash) ^ bytes[i];

    return hash;
}

bool
io_equal_uint64_ptr(const void *k1, const void *k2) {
    uint64_t u1, u2;

    u1 = *(uint64_t *)k1;
    u2 = *(uint64_t *)k2;

    return u1 == u2;
}

uint32_t
io_hash_pid_ptr(const void *arg) {
    const uint8_t *data;
    uint32_t hash;

    data = (const uint8_t *)arg;

    hash = 5381;
    for (size_t i = 0; i < sizeof(pid_t); i++)
        hash = ((hash << 5) + hash) ^ data[i];

    return hash;
}

bool
io_equal_pid_ptr(const void *arg1, const void *arg2) {
    pid_t pid1, pid2;

    pid1 = *(pid_t *)arg1;
    pid2 = *(pid_t *)arg2;

    return pid1 == pid2;
}
