/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 */
#include "dr_api.h"
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <errno.h>

static bool checked;
static unsigned checks;
static void require(bool condition, const char *what) {
    if (!condition) {
        dr_fprintf(STDERR, "RETURNING_GUARD failed=%s\n", what);
        dr_exit_process(102);
    }
    ++checks;
}
static void same_error(void *dc, int number, const reg_t *args) {
    dr_syscall_invoke_result_t original = { 0 }, guarded = { 0 };
    require(dr_invoke_syscall_as_app_with_result(dc, number, 6, args, &original),
            "original error invocation");
    require(dr_invoke_syscall_as_app_with_shared_vm_guard(
                dc, number, 6, args, 0, &guarded) == DR_SYSCALL_INVOKE_COMPLETED,
            "guard preserves established error");
    require((ptr_int_t)original.value < 0 && guarded.value == original.value &&
                guarded.interruption == original.interruption,
            "same real error");
    dr_fprintf(STDERR, "RETURNING_GUARD error sysnum=%d value=%d\n",
               number, (int)(ptr_int_t)guarded.value);
}
static bool filter(void *dc, int number) { return true; }
static bool before(void *dc, int number) {
    if (checked || number != SYS_getpid)
        return true;
    checked = true;
    dr_syscall_invoke_result_t result = { 99, 99 };
    reg_t args[6] = { 0x350f00, 0, 0, 0, 0, 0 };
    require(dr_invoke_syscall_as_app_with_shared_vm_guard(
                dc, SYS_clone, 6, args, 0, &result) == DR_SYSCALL_INVOKE_SHARED_VM_REFUSED,
            "clone shared VM refused");
    require(result.value == 0 && result.interruption == 0, "clear clone result");
    memset(args, 0, sizeof(args));
    result.value = result.interruption = 99;
    require(dr_invoke_syscall_as_app_with_shared_vm_guard(
                dc, SYS_vfork, 6, args, 0, &result) == DR_SYSCALL_INVOKE_SHARED_VM_REFUSED,
            "vfork refused");
    require(result.value == 0 && result.interruption == 0, "clear vfork result");
    args[0] = 0x800 | 17; /* SIGHAND without VM: existing EINVAL path. */
    same_error(dc, SYS_clone, args);
    args[0] = 0; args[1] = 0;
    same_error(dc, SYS_clone3, args); /* established ENOSYS or size EINVAL */
    args[0] = 1; args[1] = 88;
    same_error(dc, SYS_clone3, args); /* established ENOSYS or full-copy EFAULT */
    uint64_t clone_args[11] = { 0x350f00 };
    args[0] = (reg_t)clone_args; args[1] = sizeof(clone_args);
    dr_syscall_invoke_status_t status = dr_invoke_syscall_as_app_with_shared_vm_guard(
        dc, SYS_clone3, 6, args, 0, &result);
    require(status == DR_SYSCALL_INVOKE_SHARED_VM_REFUSED ||
                (status == DR_SYSCALL_INVOKE_COMPLETED &&
                 (ptr_int_t)result.value == -ENOSYS), "owned clone3 classification");
    dr_fprintf(STDERR, "RETURNING_GUARD clone3 status=%d value=%d\n",
               (int)status, (int)(ptr_int_t)result.value);
    memset(args, 0, sizeof(args));
    require(dr_invoke_syscall_as_app_with_shared_vm_guard(
                dc, SYS_getpid, 0, args, 0, &result) == DR_SYSCALL_INVOKE_COMPLETED &&
                result.value == (reg_t)dr_get_process_id(), "subsequent invocation");
    dr_fprintf(STDERR, "RETURNING_GUARD checks=%u completed=1\n", checks);
    return true; /* Actual guest getpid and clone still run originally. */
}
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_register_filter_syscall_event(filter);
    dr_register_pre_syscall_event(before);
}
