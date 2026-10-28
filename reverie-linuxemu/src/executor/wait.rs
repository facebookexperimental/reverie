/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! wait4 and waitid (gVisor: pkg/sentry/syscalls/linux/sys_thread.go).

use super::*;

pub(super) fn wait4_options_supported(raw: u64) -> bool {
    // Linux decodes options as int. WUNTRACED adds stopped-child eligibility;
    // it does not exclude the terminal statuses already represented here.
    // Terminal-only admission relies on stops remaining unsupported:
    // kill_signal/send_thread_signal refuse Stop, validate_deferred_signal_event
    // refuses SIGSTOP, and validate_child_exit_signal_event refuses CLD_STOPPED.
    // vm::deliver_selected_signal_at_boundary and parked_signal_runtime's
    // observe_parked_signal_impl also refuse a remaining Stop disposition.
    // Adding stopped children requires extending wait4 before changing the
    // wait4_wuntraced_requires_unsupported_stopped_children contract test.
    // WCONTINUED remains unsupported.
    let options = raw as libc::c_int;
    options & !(libc::WNOHANG | libc::WUNTRACED) == 0
}

pub(super) fn wait_group_exit_status(state: &LoadedStaticElf) -> Option<ExitStatus> {
    let identity = state.children.task_identity().ok()?;
    if identity.tid.as_raw() != state.tid || identity.process.tgid.as_raw() != state.pid {
        return None;
    }
    state
        .task_lifecycle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .live_task_group_exit_status(identity)
}

fn parent_terminated_wait(state: &LoadedStaticElf) -> crate::Result<i64> {
    Err(match wait_group_exit_status(state) {
        Some(status) => crate::Error::ChildWaitGroupExit { status },
        None => crate::Error::RunAborted,
    })
}

/// Shared-file scalar copyout has no fault-contained atomic host primitive.
/// Refuse that capability before consuming a child. Ordinary permission faults
/// retain Linux's existing consume-then-copyout behavior: they are NOT moved
/// ahead of selection, and earlier faulting fields still win over later ones.
pub(super) fn preflight_wait_shared_outputs(
    memory: &GuestMemory,
    args: &[u64; 6],
    waitid_call: bool,
) -> crate::Result<()> {
    let address = if waitid_call { args[2] } else { args[1] };
    if address == 0 || (waitid_call && address >= X86_64_GUEST_USER_LIMIT) {
        return Ok(());
    }
    let offsets: &[u64] = if waitid_call {
        &[0, 4, 8, 16, 20, 24]
    } else {
        &[0]
    };
    if !offsets.iter().any(|offset| {
        address
            .checked_add(*offset)
            .is_some_and(|address| memory.user_range_contains_shared_file(address, 4))
    }) {
        return Ok(());
    }
    for offset in offsets {
        let Some(field) = address.checked_add(*offset) else {
            return Ok(());
        };
        if waitid_call && field + 4 > X86_64_GUEST_USER_LIMIT {
            return Ok(());
        }
        match memory.user().preflight_atomic_store(field, 4) {
            Ok(()) => {}
            Err(
                crate::Error::InvalidGuestAddress { .. }
                | crate::Error::GuestMemoryAccessDenied { .. },
            ) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(super) fn wait4_result(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> crate::Result<i64> {
    // Linux pid_t is signed low32. Retain the existing raw backend's single
    // group selector approximation; this change does not add PGID support.
    let requested = args[0] as i32;
    if !wait4_options_supported(args[2]) {
        return Ok(negative_errno(libc::EINVAL));
    }
    let nonblocking = args[2] as libc::c_int & libc::WNOHANG != 0;
    if args[1] != 0 && memory.user_range_contains_shared_file(args[1], 4) {
        // This observation never consumes a ready child. A no-result return
        // does not attempt a status store, so its native ECHILD/zero result
        // precedes the shared scalar capability check. A ready or potentially
        // blocking result still refuses before any consuming selection.
        match state
            .children
            .select((requested > 0).then_some(requested), false, true)?
        {
            ChildWaitSelection::NoChild => return Ok(negative_errno(libc::ECHILD)),
            ChildWaitSelection::Pending if nonblocking => return Ok(0),
            ChildWaitSelection::ParentTerminated => return parent_terminated_wait(state),
            ChildWaitSelection::Pending | ChildWaitSelection::Ready(_) => {}
        }
    }
    preflight_wait_shared_outputs(memory, args, false)?;
    let selected =
        match state
            .children
            .select((requested > 0).then_some(requested), true, nonblocking)?
        {
            ChildWaitSelection::Ready(selected) => selected,
            ChildWaitSelection::ParentTerminated => return parent_terminated_wait(state),
            ChildWaitSelection::Pending => return Ok(0),
            ChildWaitSelection::NoChild => return Ok(negative_errno(libc::ECHILD)),
        };
    let child_pid = selected.child.tgid.as_raw();
    let status = selected.status.into_raw();
    // Selection already consumed the exact family edge. Preserve that receipt
    // through either output fault: status is nonpartial and precedes bulk usage.
    state.consumed_child_wait = selected.receipt;
    if args[1] != 0 && memory.user().put_user_i32(args[1], status).is_err() {
        return Ok(negative_errno(libc::EFAULT));
    }
    if args[3] != 0
        && memory
            .user()
            .copy_to_user(args[3], &[0; std::mem::size_of::<libc::rusage>()])
            .is_err()
    {
        return Ok(negative_errno(libc::EFAULT));
    }
    Ok(i64::from(child_pid))
}

#[cfg(test)]
pub(super) fn wait4(memory: &mut GuestMemory, state: &mut LoadedStaticElf, args: &[u64; 6]) -> i64 {
    wait4_result(memory, state, args).expect("raw wait4 fixture has a coherent family ledger")
}

#[repr(C)]
pub(super) struct GuestWaitidSiginfo {
    pub(super) si_signo: libc::c_int,
    pub(super) si_errno: libc::c_int,
    pub(super) si_code: libc::c_int,
    pub(super) _union_alignment: libc::c_int,
    pub(super) si_pid: libc::pid_t,
    pub(super) si_uid: libc::uid_t,
    pub(super) si_status: libc::c_int,
    pub(super) _clock_alignment: libc::c_int,
    pub(super) _si_utime: libc::c_long,
    pub(super) _si_stime: libc::c_long,
    pub(super) _padding: [u8; std::mem::size_of::<libc::siginfo_t>() - 48],
}

pub(super) fn waitid_options_supported(raw: u64) -> bool {
    // Linux decodes options as int. Retain the existing terminal-only subset;
    // accepting stopped/continued events needs separate backend support.
    let options = raw as libc::c_int;
    let allowed = libc::WEXITED | libc::WNOHANG | libc::WNOWAIT;
    options & libc::WEXITED != 0 && options & !allowed == 0
}

pub(super) fn finish_waitid<M: GuestMemoryAccess<Error = crate::Error>>(
    memory: &M,
    args: &[u64; 6],
    event: Option<&GuestWaitidSiginfo>,
    result: i64,
) -> i64 {
    // Only a positive event writes rusage, before any siginfo field. Preserve
    // the backend's existing zero accounting and the writable-prefix copy.
    if event.is_some() && args[4] != 0 {
        let size = std::mem::size_of::<libc::rusage>();
        if validate_guest_iovec_address(args[4], size).is_err()
            || memory
                .copy_to_user(args[4], &[0; std::mem::size_of::<libc::rusage>()])
                .is_err()
        {
            return negative_errno(libc::EFAULT);
        }
    }
    if args[2] == 0 {
        return result;
    }
    // x86-64 Linux's constant-size access_ok does not validate a full siginfo
    // span. Only the six scalar fields are accessed. The architectural guard
    // page still faults even if a synthetic GuestMemory arena maps beyond it.
    if args[2] >= X86_64_GUEST_USER_LIMIT {
        return negative_errno(libc::EFAULT);
    }
    let fields = event.map_or([0; 6], |info| {
        [
            info.si_signo,
            info.si_errno,
            info.si_code,
            info.si_pid,
            info.si_uid as libc::c_int,
            info.si_status,
        ]
    });
    for (offset, value) in [0_u64, 4, 8, 16, 20, 24].into_iter().zip(fields) {
        // The bounded starting address makes this addition nonoverflowing.
        // Stop before a scalar crosses the architectural guard: earlier fields
        // remain, and the failing scalar, padding and tail stay untouched.
        let address = args[2] + offset;
        if address + 4 > X86_64_GUEST_USER_LIMIT || memory.put_user_i32(address, value).is_err() {
            return negative_errno(libc::EFAULT);
        }
    }
    result
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-227): Review serialized-child waitid ABI emulation.
pub(super) fn waitid_result(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> crate::Result<i64> {
    if !waitid_options_supported(args[3]) {
        return Ok(finish_waitid(
            &ProviderMemory(memory),
            args,
            None,
            negative_errno(libc::EINVAL),
        ));
    }
    let requested = match args[0] as libc::idtype_t {
        libc::P_PID => match i32::try_from(args[1]) {
            Ok(pid) => Some(pid),
            Err(_) => {
                return Ok(finish_waitid(
                    &ProviderMemory(memory),
                    args,
                    None,
                    negative_errno(libc::ECHILD),
                ));
            }
        },
        libc::P_ALL | libc::P_PGID => None,
        _ => {
            return Ok(finish_waitid(
                &ProviderMemory(memory),
                args,
                None,
                negative_errno(libc::EINVAL),
            ));
        }
    };
    preflight_wait_shared_outputs(memory, args, true)?;
    let selected = match state.children.select(
        requested,
        args[3] as libc::c_int & libc::WNOWAIT == 0,
        args[3] as libc::c_int & libc::WNOHANG != 0,
    )? {
        ChildWaitSelection::Ready(selected) => selected,
        ChildWaitSelection::ParentTerminated => return parent_terminated_wait(state),
        ChildWaitSelection::Pending => {
            return Ok(finish_waitid(&ProviderMemory(memory), args, None, 0));
        }
        ChildWaitSelection::NoChild => {
            return Ok(finish_waitid(
                &ProviderMemory(memory),
                args,
                None,
                negative_errno(libc::ECHILD),
            ));
        }
    };
    let child_pid = selected.child.tgid.as_raw();
    let status = selected.status;
    state.consumed_child_wait = selected.receipt;
    let (si_code, si_status) = match status {
        ExitStatus::Exited(code) => (libc::CLD_EXITED, code),
        ExitStatus::Signaled(signal, true) => (libc::CLD_DUMPED, signal as libc::c_int),
        ExitStatus::Signaled(signal, false) => (libc::CLD_KILLED, signal as libc::c_int),
        ExitStatus::SignaledRaw(signal, true) => (libc::CLD_DUMPED, signal),
        ExitStatus::SignaledRaw(signal, false) => (libc::CLD_KILLED, signal),
    };
    let info = GuestWaitidSiginfo {
        si_signo: libc::SIGCHLD,
        si_errno: 0,
        si_code,
        _union_alignment: 0,
        si_pid: child_pid,
        si_uid: 0,
        si_status,
        _clock_alignment: 0,
        _si_utime: 0,
        _si_stime: 0,
        _padding: [0; std::mem::size_of::<libc::siginfo_t>() - 48],
    };
    Ok(finish_waitid(&ProviderMemory(memory), args, Some(&info), 0))
}

#[cfg(test)]
pub(super) fn waitid(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    args: &[u64; 6],
) -> i64 {
    waitid_result(memory, state, args).expect("raw waitid fixture has a coherent family ledger")
}
