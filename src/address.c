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

#include <stdio.h>

#include <sys/socket.h>
#include <sys/types.h>

#include "internal.h"

static struct sockaddr_in *io_address_sockaddr_in(const struct io_address *);
static struct sockaddr_in6 *io_address_sockaddr_in6(const struct io_address *);

static int io_address_update_strings(struct io_address *);

int
io_address_init(struct io_address *address, const char *host, uint16_t port) {
    char service[NI_MAXSERV];
    struct addrinfo hints, *res;
    int ret;

    snprintf(service, NI_MAXSERV, "%u", port);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    ret = getaddrinfo(host, service, &hints, &res);
    if (ret != 0) {
        c_set_error("cannot resolve %s:%u: %s", host, port, gai_strerror(ret));
        return -1;
    }

    if (io_address_init_from_sockaddr(address,
                                      res->ai_addr, res->ai_addrlen) == -1) {
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);

    if (io_address_update_strings(address) == -1) {
        c_set_error("cannot format address strings: %s", c_get_error());
        return -1;
    }

    return 0;
}

int
io_address_init_from_sockaddr(struct io_address *address,
                              const struct sockaddr *sa, socklen_t salen) {
    switch (sa->sa_family) {
    case AF_INET:
    case AF_INET6:
        break;

    default:
        c_set_error("unknown socket address family %d", sa->sa_family);
        return -1;
    }

    memset(address, 0, sizeof(struct io_address));

    memcpy(&address->ss, sa, salen);
    address->sslen = salen;

    if (io_address_update_strings(address) == -1) {
        c_set_error("cannot format address strings: %s", c_get_error());
        return -1;
    }

    return 0;
}

int
io_address_init_from_sockaddr_storage(struct io_address *address,
                                      const struct sockaddr_storage *ss) {
    socklen_t len;

#if defined(IO_PLATFORM_LINUX)
    len = sizeof(struct sockaddr_storage);
#elif defined(IO_PLATFORM_FREEBSD)
    len = ss->ss_len;
#else
#   error "io_address_init_from_sockaddr_storage() is not supported on this platform"
#endif

    return io_address_init_from_sockaddr(address,
                                         (const struct sockaddr *)ss, len);
}

int
io_address_resolve(const char *host, uint16_t port, sa_family_t family,
                   int type, int proto,
                   struct io_address **paddrs, size_t *p_nb_addrs) {
    char service[NI_MAXSERV];
    struct addrinfo hints, *res, *ai;
    struct io_address *addrs;
    size_t nb_addrs, i;
    int ret;

    snprintf(service, NI_MAXSERV, "%u", port);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = family;
    hints.ai_socktype = type;
    hints.ai_protocol = proto;

    ret = getaddrinfo(host, service, &hints, &res);
    if (ret != 0) {
        c_set_error("cannot resolve %s:%u: %s", host, port, gai_strerror(ret));
        return -1;
    }

    nb_addrs = 0;
    ai = res;
    while (ai) {
        nb_addrs++;
        ai = ai->ai_next;
    }

    addrs = c_calloc(nb_addrs, sizeof(struct io_address));

    i = 0;
    ai = res;
    while (ai) {
        struct io_address *addr;

        addr = addrs + i;

        if (io_address_init_from_sockaddr(addr,
                                          ai->ai_addr, ai->ai_addrlen) == -1) {
            goto error;
        }

        if (io_address_update_strings(addr) == -1) {
            c_set_error("cannot format address strings: %s", c_get_error());
            goto error;
        }

        i++;
        ai = ai->ai_next;
    }


    freeaddrinfo(res);

    *paddrs = addrs;
    *p_nb_addrs = nb_addrs;
    return 0;

error:
    freeaddrinfo(res);
    c_free(addrs);
    return -1;
}

int
io_address_family(const struct io_address *address) {
    return address->ss.ss_family;
}

uint16_t
io_address_port(const struct io_address *address) {
    struct sockaddr_in *sa;
    struct sockaddr_in6 *sa6;
    uint16_t port;

    switch (address->ss.ss_family) {
    case AF_INET:
        sa = io_address_sockaddr_in(address);
        port = sa->sin_port;
        break;

    case AF_INET6:
        sa6 = io_address_sockaddr_in6(address);
        port = sa6->sin6_port;
        break;

    default:
        port = 0;
        break;
    }

    return ntohs(port);
}

const char *
io_address_host_string(const struct io_address *address) {
    return address->host_string;
}

const char *
io_address_host_port_string(const struct io_address *address) {
    return address->host_port_string;
}

struct sockaddr *
io_address_sockaddr(const struct io_address *address) {
    return (struct sockaddr *)&address->ss;
}

socklen_t
io_address_length(const struct io_address *address) {
    return address->sslen;
}

void
io_address_set_port(struct io_address *address, uint16_t port) {
    struct sockaddr_in *sa;
    struct sockaddr_in6 *sa6;
    uint16_t *pport;

    switch (address->ss.ss_family) {
    case AF_INET:
        sa = io_address_sockaddr_in(address);
        pport = &sa->sin_port;
        break;

    case AF_INET6:
        sa6 = io_address_sockaddr_in6(address);
        pport = &sa6->sin6_port;
        break;

    default:
        return;
    }

    *pport = ntohs(port);

    io_address_update_strings(address);
}

static struct sockaddr_in *
io_address_sockaddr_in(const struct io_address *address) {
    assert(address->ss.ss_family == AF_INET);
    return (struct sockaddr_in *)&address->ss;
}

static struct sockaddr_in6 *
io_address_sockaddr_in6(const struct io_address *address) {
    assert(address->ss.ss_family == AF_INET6);
    return (struct sockaddr_in6 *)&address->ss;
}

static int
io_address_update_strings(struct io_address *address) {
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    int ret;

    ret = getnameinfo((const struct sockaddr *)&address->ss, address->sslen,
                      host, NI_MAXHOST, service, NI_MAXSERV,
                      NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret != 0) {
        c_set_error("cannot format address: %s", gai_strerror(ret));
        return -1;
    }

    if (address->ss.ss_family == AF_INET6) {
        snprintf(address->host_string, IO_ADDRESS_HOST_BUFSIZ,
                 "[%s]", host);
        snprintf(address->host_port_string, IO_ADDRESS_HOST_PORT_BUFSIZ,
                 "[%s]:%s", host, service);
    } else {
        c_strlcpy(address->host_string, host, IO_ADDRESS_HOST_BUFSIZ);
        snprintf(address->host_port_string, IO_ADDRESS_HOST_PORT_BUFSIZ,
                 "%s:%s", host, service);
    }

    return 0;
}
