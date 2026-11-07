/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

#include "dr_api.h"

static void report_option(const char *phase) {
    uint64 value = 0;
    if (!dr_get_integer_option("vm_max_offset", &value)) {
        dr_fprintf((file_t)198, "PRIVATE_PLACEMENT query-failed\n");
        dr_abort_with_code(90);
    }
    dr_fprintf((file_t)198, "PRIVATE_PLACEMENT phase=%s value=%llu\n", phase,
               (unsigned long long)value);
}

static void after_fork(void *context) {
    (void)context;
    report_option("fork");
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    (void)id;
    (void)argc;
    (void)argv;
    dr_register_fork_init_event(after_fork);
    report_option("init");
}
