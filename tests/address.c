/*
 * Copyright (c) 2015 Celticom
 * Developed by Nicolas Martyanoff
 */

#include <arpa/inet.h>
#include <netinet/in.h>

#include <utest.h>

#include "io.h"

TEST(init) {
    struct io_address addr;

    TEST_INT_EQ(io_address_init(&addr, "foo", 0), -1);
    TEST_INT_EQ(io_address_init(&addr, "127.0.0.", 0), -1);
    TEST_INT_EQ(io_address_init(&addr, "1.2.3.4.5", 0), -1);
    TEST_INT_EQ(io_address_init(&addr, "[::1]", 0), -1);

    TEST_INT_EQ(io_address_init(&addr, "127.0.0.1", 0), 0);
    TEST_INT_EQ(io_address_family(&addr), AF_INET);
    TEST_UINT_EQ(io_address_port(&addr), 0);
    TEST_STRING_EQ(io_address_host_string(&addr), "127.0.0.1");
    TEST_STRING_EQ(io_address_host_port_string(&addr), "127.0.0.1:0");

    TEST_INT_EQ(io_address_init(&addr, "10.0.0.1", 8080), 0);
    TEST_INT_EQ(io_address_family(&addr), AF_INET);
    TEST_UINT_EQ(io_address_port(&addr), 8080);
    TEST_STRING_EQ(io_address_host_string(&addr), "10.0.0.1");
    TEST_STRING_EQ(io_address_host_port_string(&addr), "10.0.0.1:8080");

    TEST_INT_EQ(io_address_init(&addr, "::1", 65535), 0);
    TEST_INT_EQ(io_address_family(&addr), AF_INET6);
    TEST_UINT_EQ(io_address_port(&addr), 65535);
    TEST_STRING_EQ(io_address_host_string(&addr), "[::1]");
    TEST_STRING_EQ(io_address_host_port_string(&addr), "[::1]:65535");

    TEST_INT_EQ(io_address_init(&addr, "fe80::ed61:2057:9f89:447f", 1234), 0);
    TEST_INT_EQ(io_address_family(&addr), AF_INET6);
    TEST_UINT_EQ(io_address_port(&addr), 1234);
    TEST_STRING_EQ(io_address_host_string(&addr),
                   "[fe80::ed61:2057:9f89:447f]");
    TEST_STRING_EQ(io_address_host_port_string(&addr),
                   "[fe80::ed61:2057:9f89:447f]:1234");
}

TEST(init_from_sockaddr) {
    struct io_address addr;
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;

#define IOT_INIT_FROM_SA(addr_, sa_, salen_)                        \
    do {                                                            \
        const struct sockaddr *sa__;                                \
                                                                    \
        sa__ = (const struct sockaddr *)(sa_);                      \
        if (io_address_init_from_sockaddr(addr_, sa__, salen_) == -1) \
            TEST_ABORT("cannot init address: %s", c_get_error());   \
    } while (0)

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = ntohs(8080);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr.s_addr);
    IOT_INIT_FROM_SA(&addr, &sa, sizeof(sa));
    TEST_INT_EQ(io_address_family(&addr), AF_INET);
    TEST_UINT_EQ(io_address_port(&addr), 8080);
    TEST_STRING_EQ(io_address_host_string(&addr), "127.0.0.1");
    TEST_STRING_EQ(io_address_host_port_string(&addr), "127.0.0.1:8080");

    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
    sa6.sin6_port = ntohs(1234);
    inet_pton(AF_INET6, "fe80::ed61:2057:9f89:447f", sa6.sin6_addr.s6_addr);
    IOT_INIT_FROM_SA(&addr, &sa6, sizeof(sa6));
    TEST_INT_EQ(io_address_family(&addr), AF_INET6);
    TEST_UINT_EQ(io_address_port(&addr), 1234);
    TEST_STRING_EQ(io_address_host_string(&addr),
                   "[fe80::ed61:2057:9f89:447f]");
    TEST_STRING_EQ(io_address_host_port_string(&addr),
                   "[fe80::ed61:2057:9f89:447f]:1234");

#undef IOT_INIT_FROM_SA
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("address");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, init);
    TEST_RUN(suite, init_from_sockaddr);

    test_suite_print_results_and_exit(suite);
}
