/*
 * Copyright (c) 2015 Celticom
 * Developed by Nicolas Martyanoff
 */

#include <utest.h>

#include "internal.h"

struct io_watcher *iot_watcher_new_dummy(int);

#define IOT_WATCHER_DUMMY_EQ(watcher_, value_) \
    TEST_INT_EQ((watcher_)->u.fd.fd, value_)

TEST(base) {
    struct io_watcher_array array;
    struct io_watcher *watcher;

    io_watcher_array_init(&array);
    TEST_UINT_EQ(array.nb_watchers, 0);

    io_watcher_array_add(&array, 1, iot_watcher_new_dummy(1));
    TEST_UINT_EQ(array.nb_watchers, 1);
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 1), 1);

    io_watcher_array_add(&array, 3, iot_watcher_new_dummy(3));
    io_watcher_array_add(&array, 4, iot_watcher_new_dummy(4));
    io_watcher_array_add(&array, 5, iot_watcher_new_dummy(5));
    io_watcher_array_add(&array, 9, iot_watcher_new_dummy(9));
    TEST_UINT_EQ(array.nb_watchers, 5);
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 1), 1);
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 3), 3);
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 4), 4);
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 5), 5);
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 9), 9);

    watcher = io_watcher_array_get(&array, 1);
    io_watcher_array_remove(&array, 1);
    TEST_UINT_EQ(array.nb_watchers, 4);
    TEST_PTR_NULL(io_watcher_array_get(&array, 1));
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 3), 3);
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 4), 4);
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 5), 5);
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 9), 9);
    io_watcher_delete(watcher);

    watcher = io_watcher_array_get(&array, 9);
    io_watcher_array_remove(&array, 9);
    TEST_UINT_EQ(array.nb_watchers, 3);
    TEST_PTR_NULL(io_watcher_array_get(&array, 9));
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 3), 3);
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 4), 4);
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 5), 5);
    io_watcher_delete(watcher);

    watcher = io_watcher_array_get(&array, 4);
    io_watcher_array_remove(&array, 4);
    TEST_UINT_EQ(array.nb_watchers, 2);
    TEST_PTR_NULL(io_watcher_array_get(&array, 4));
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 3), 3);
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 5), 5);
    io_watcher_delete(watcher);

    watcher = io_watcher_array_get(&array, 3);
    io_watcher_array_remove(&array, 3);
    TEST_UINT_EQ(array.nb_watchers, 1);
    TEST_PTR_NULL(io_watcher_array_get(&array, 3));
    IOT_WATCHER_DUMMY_EQ(io_watcher_array_get(&array, 5), 5);
    io_watcher_delete(watcher);

    watcher = io_watcher_array_get(&array, 5);
    io_watcher_array_remove(&array, 5);
    TEST_PTR_NULL(io_watcher_array_get(&array, 5));
    TEST_UINT_EQ(array.nb_watchers, 0);
    io_watcher_delete(watcher);

    io_watcher_array_free(&array);
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("watcher-array");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, base);

    test_suite_print_results_and_exit(suite);
}

struct io_watcher *
iot_watcher_new_dummy(int value) {
    struct io_watcher *watcher;

    watcher = io_watcher_new(IO_WATCHER_FD);
    watcher->u.fd.fd = value;

    return watcher;
}
