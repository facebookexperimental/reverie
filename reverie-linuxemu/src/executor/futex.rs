/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Futexes and robust lists (gVisor: pkg/sentry/kernel/futex, kernel/task_futex.go).

use super::*;

// TODO-HUMAN-REVIEW(PR-172): Review host-backed futex address and timeout translation.
pub(super) fn futex<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &M,
    args: &[u64; 6],
) -> i64 {
    let operation = args[1] as libc::c_int;
    let command = operation & libc::FUTEX_CMD_MASK;
    // sys_futex imports and validates timeout-bearing commands before
    // do_futex observes either futex word. Own that copied value instead of
    // retaining a guest mapping for the duration of a blocking host wait.
    let timeout = if args[3] != 0
        && matches!(
            command,
            libc::FUTEX_WAIT
                | libc::FUTEX_LOCK_PI
                | libc::FUTEX_WAIT_BITSET
                | libc::FUTEX_WAIT_REQUEUE_PI
                | libc::FUTEX_LOCK_PI2
        ) {
        let timeout = match read_guest_struct::<libc::timespec>(memory, args[3]) {
            Ok(timeout) => timeout,
            Err(error) => return error,
        };
        if timeout.tv_sec < 0 || !(0..1_000_000_000).contains(&timeout.tv_nsec) {
            return negative_errno(libc::EINVAL);
        }
        Some(timeout)
    } else {
        None
    };

    // do_futex rejects unsupported commands and clock-flag combinations
    // before get_futex_key inspects either word.
    if operation & libc::FUTEX_CLOCK_REALTIME != 0
        && !matches!(
            command,
            libc::FUTEX_WAIT_BITSET | libc::FUTEX_WAIT_REQUEUE_PI | libc::FUTEX_LOCK_PI2
        )
    {
        return negative_errno(libc::ENOSYS);
    }
    if !matches!(
        command,
        libc::FUTEX_WAIT
            | libc::FUTEX_WAKE
            | libc::FUTEX_REQUEUE
            | libc::FUTEX_CMP_REQUEUE
            | libc::FUTEX_WAKE_OP
            | libc::FUTEX_LOCK_PI
            | libc::FUTEX_UNLOCK_PI
            | libc::FUTEX_TRYLOCK_PI
            | libc::FUTEX_WAIT_BITSET
            | libc::FUTEX_WAKE_BITSET
            | libc::FUTEX_WAIT_REQUEUE_PI
            | libc::FUTEX_CMP_REQUEUE_PI
            | libc::FUTEX_LOCK_PI2
    ) {
        return negative_errno(libc::ENOSYS);
    }

    // These non-PI handlers enter get_futex_key before any error with a
    // different errno, and key lookup rejects natural-alignment violations
    // before inspecting the word. PI handlers have earlier configuration,
    // allocation, ownership, or second-word work, so retain their existing
    // adapter ordering. Host placement must not decide the covered cases.
    if matches!(
        command,
        libc::FUTEX_WAIT
            | libc::FUTEX_WAKE
            | libc::FUTEX_REQUEUE
            | libc::FUTEX_CMP_REQUEUE
            | libc::FUTEX_WAKE_OP
            | libc::FUTEX_WAIT_BITSET
            | libc::FUTEX_WAKE_BITSET
    ) && !args[0].is_multiple_of(std::mem::size_of::<u32>() as u64)
    {
        return negative_errno(libc::EINVAL);
    }
    let Ok(uaddr) = guest_host_address(memory, args[0], std::mem::size_of::<u32>()) else {
        return negative_errno(libc::EFAULT);
    };

    let mut second_operand = None;
    let fourth = timeout
        .as_ref()
        .map_or(args[3] as usize, |value| std::ptr::from_ref(value) as usize);
    let uaddr2 = if matches!(
        command,
        libc::FUTEX_REQUEUE
            | libc::FUTEX_CMP_REQUEUE
            | libc::FUTEX_WAKE_OP
            | libc::FUTEX_WAIT_REQUEUE_PI
            | libc::FUTEX_CMP_REQUEUE_PI
    ) {
        if matches!(
            command,
            libc::FUTEX_REQUEUE | libc::FUTEX_CMP_REQUEUE | libc::FUTEX_WAKE_OP
        ) && !args[4].is_multiple_of(std::mem::size_of::<u32>() as u64)
        {
            return negative_errno(libc::EINVAL);
        }
        match guest_host_address(memory, args[4], std::mem::size_of::<u32>()) {
            Ok(operand) => {
                let address = operand.host_address();
                second_operand = Some(operand);
                address
            }
            Err(error) => return error,
        }
    } else {
        0
    };

    // SAFETY: uaddr and an optional uaddr2 remain retained in the shared guest
    // mapping for the whole syscall. For timeout-bearing commands, fourth
    // points to the host-owned `timeout` storage kept alive below; otherwise it
    // is the scalar fourth argument. The kernel does not retain these pointers
    // after the synchronous syscall returns.
    let result = unsafe {
        libc::syscall(
            libc::SYS_futex,
            uaddr.host_address(),
            operation,
            args[2] as u32,
            fourth,
            uaddr2,
            args[5] as u32,
        )
    };
    let result = if result < 0 {
        io_error(std::io::Error::last_os_error())
    } else {
        result as i64
    };
    drop((uaddr, second_operand, timeout));
    result
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-232): Review task-local robust-list registration.
pub(super) fn set_robust_list(state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    if args[1] != ROBUST_LIST_HEAD_SIZE {
        return negative_errno(libc::EINVAL);
    }
    let updated = state
        .task_lifecycle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .set_robust_list(state.tid, args[0]);
    debug_assert!(
        updated,
        "current KVM task is absent from its lifecycle table"
    );
    if !updated {
        return negative_errno(libc::ESRCH);
    }
    0
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-232): Review process-tree robust-list queries.
pub(super) fn get_robust_list(
    memory: &mut GuestMemory,
    state: &LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    let requested = match args[0] as libc::pid_t {
        0 => state.tid,
        tid => tid,
    };
    let Some(target) = state
        .task_lifecycle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(requested)
    else {
        return negative_errno(libc::ESRCH);
    };

    // Every task has the fixed virtual-root credentials. Match the remaining
    // ptrace access predicates: same-thread-group reads are always allowed;
    // cross-process reads require either a dumpable target or CAP_SYS_PTRACE.
    if target.tgid != state.pid
        && !target.dumpable
        && state.capability_effective & (1_u64 << CAP_SYS_PTRACE) == 0
    {
        return negative_errno(libc::EPERM);
    }

    // Linux resolves and authorizes the target first, then writes the fixed
    // header size before the head pointer. Preserve that partial-copy ordering.
    if args[2] == 0 || write_u64(&mut ProviderMemory(memory), args[2], ROBUST_LIST_HEAD_SIZE) != 0 {
        return negative_errno(libc::EFAULT);
    }
    if args[1] == 0
        || write_u64(
            &mut ProviderMemory(memory),
            args[1],
            target.robust_list_head,
        ) != 0
    {
        return negative_errno(libc::EFAULT);
    }
    0
}
