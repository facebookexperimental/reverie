/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Typed refusals for unsupported operations (Reverie's `UnsupportedRefusal`); gVisor reports these as unimplemented syscalls.

use super::*;

pub(super) const MAX_HOST_IO: usize = 16 * 1024 * 1024;
pub(super) const MAX_CAPTURED_OUTPUT: usize = 64 * 1024 * 1024;
pub(super) const PAGE_SIZE: u64 = 4096;
pub(super) const MAX_RW_COUNT: usize = (i32::MAX as usize) & !(PAGE_SIZE as usize - 1);
pub(super) use reverie_kvm_core::host_limits::HostResource;
pub(super) use reverie_kvm_core::host_limits::HostResourceExhaustion;
pub use reverie_kvm_core::layout::GUEST_USER_ADDRESS_LIMIT;
pub use reverie_kvm_core::layout::X86_64_GUEST_USER_LIMIT;
/// Diagnostic carried by this backend's typed refusal of an exec from a thread
/// that is not its group's leader.
pub(crate) const NONLEADER_EXEC_REFUSAL: &str = "KVM nonleader exec is unsupported";

/// The typed refusal, if any, that an exec result from thread `tid` of
/// process `pid` carries.
///
/// Linux's execve never fails with ENOSYS, so every ENOSYS this backend
/// returns to a non-leader exec is its own refusal. That covers the explicit
/// refusal after image preflight and an ENOSYS from a host syscall the
/// preflight makes, such as the host `faccessat2` permission check on a
/// kernel or sandbox that lacks it. Every other result, and every result for
/// a group leader, carries none.
pub(super) fn nonleader_exec_refusal(
    result: i64,
    tid: i32,
    pid: i32,
) -> Option<reverie::UnsupportedRefusal> {
    (result == negative_errno(libc::ENOSYS) && tid != pid).then(|| {
        reverie::UnsupportedRefusal::new(
            reverie::UnsupportedOperation::NonLeaderExec,
            reverie::Errno::ENOSYS,
            NONLEADER_EXEC_REFUSAL,
        )
    })
}

/// Diagnostic of this backend's typed refusal of an exec whose preparation a
/// host call or allocation failed with ENOMEM, where no more specific
/// diagnostic was recorded, and the one every refusal of host resources falls
/// back to once [`MAX_HOST_RESOURCES_DIAGNOSTICS`] distinct ones are kept.
pub(crate) const HOST_RESOURCES_REFUSAL: &str = "KVM exec: host memory ran out: a host call or \
     allocation preparing the new image failed with ENOMEM";

/// The most distinct host-resource diagnostics this process keeps (see
/// [`intern_host_resources_diagnostic`]).
pub(crate) const MAX_HOST_RESOURCES_DIAGNOSTICS: usize = 64;

/// `text` as the `&'static str` that a [`reverie::UnsupportedRefusal`]
/// carries. A host-resource diagnostic names values known only when it is
/// made (the request and the limit), so each distinct text is allocated once
/// and kept for the rest of the process. That stays small: an embedder that
/// ends the run on the first refusal makes one, and one that lets the guest
/// continue repeats the same few texts, since the request (the guest memory
/// size) and the limit do not change. Past
/// [`MAX_HOST_RESOURCES_DIAGNOSTICS`] distinct texts, [`HOST_RESOURCES_REFUSAL`].
pub(super) fn intern_host_resources_diagnostic(text: String) -> &'static str {
    static KEPT: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    keep_host_resources_diagnostic(
        &mut KEPT.lock().unwrap_or_else(|poisoned| poisoned.into_inner()),
        text,
    )
}

/// [`intern_host_resources_diagnostic`], with `kept` the texts kept so far.
pub(super) fn keep_host_resources_diagnostic(
    kept: &mut Vec<&'static str>,
    text: String,
) -> &'static str {
    if let Some(existing) = kept.iter().find(|kept| **kept == text) {
        return existing;
    }
    if kept.len() >= MAX_HOST_RESOURCES_DIAGNOSTICS {
        return HOST_RESOURCES_REFUSAL;
    }
    let text: &'static str = Box::leak(text.into_boxed_str());
    kept.push(text);
    text
}

/// A typed `HostResources` refusal of an exec, answered ENOMEM, with
/// `diagnostic`.
fn exec_host_resources_refusal(diagnostic: String) -> reverie::UnsupportedRefusal {
    reverie::UnsupportedRefusal::new(
        reverie::UnsupportedOperation::HostResources,
        reverie::Errno::ENOMEM,
        intern_host_resources_diagnostic(diagnostic),
    )
}

/// The typed refusal of an exec whose preparation could not reserve the
/// `request` bytes of guest memory it validates the new image in before it
/// replaces the old one: the host refused them with `error`. Every such
/// failure is this backend's own (the layout is the caller's live one, so it
/// is valid), and no guest request decides it. The answer is ENOMEM, and the
/// diagnostic names the request, the error and the limit it ran out under:
/// this process's `RLIMIT_AS` when memory ran out (the reservation is host
/// address space), its `RLIMIT_NOFILE` when the memfd behind it found no
/// descriptor.
pub(super) fn exec_validation_memory_refusal(
    request: usize,
    error: &crate::Error,
) -> reverie::UnsupportedRefusal {
    let detail = match error {
        crate::Error::MemoryMapping(host) | crate::Error::HostIo(host) => host.to_string(),
        other => other.to_string(),
    };
    let (resource, limit) = match error.host_resource_exhaustion() {
        Some(exhaustion) if exhaustion.resource == HostResource::Memory => {
            ("host address space ran out", exhaustion.limit)
        }
        Some(exhaustion) => (exhaustion.resource.ran_out(), exhaustion.limit),
        None => (
            "a host resource ran out",
            format!(
                "this process's RLIMIT_AS ({})",
                reverie_kvm_core::host_limits::address_space_limit_text()
            ),
        ),
    };
    exec_host_resources_refusal(format!(
        "KVM exec: {resource}: reserving {request} bytes of host address space for the guest \
         memory that validates the new image failed ({detail}) under {limit}; this backend \
         reserves its guest memory size for every guest process and once more during each exec"
    ))
}

/// The typed refusal of an exec whose preparation could not allocate the
/// `request` bytes it needs for `what`: an image, or a copy of one, whose
/// size the file decides. The answer is ENOMEM, and the diagnostic names the
/// request and this process's `RLIMIT_AS`.
pub(super) fn exec_allocation_refusal(request: usize, what: &str) -> reverie::UnsupportedRefusal {
    exec_host_resources_refusal(format!(
        "KVM exec: {}: allocating {request} bytes for {what} failed under this process's \
         RLIMIT_AS ({})",
        HostResource::Memory.ran_out(),
        reverie_kvm_core::host_limits::address_space_limit_text(),
    ))
}

/// The typed refusal of an exec whose preparation failed in `step` with
/// `error` because a host resource of this process's own ran out
/// (`exhaustion`). The answer is ENOMEM, and the diagnostic names the
/// resource, the step, the error and the limit.
pub(super) fn exec_host_resource_refusal(
    step: &str,
    error: &dyn std::fmt::Display,
    exhaustion: &HostResourceExhaustion,
) -> reverie::UnsupportedRefusal {
    exec_host_resources_refusal(format!(
        "KVM exec: {}: {step} failed ({error}) under {}",
        exhaustion.resource.ran_out(),
        exhaustion.limit,
    ))
}

/// The answer to a host call that an exec preparation made in `step` and
/// that failed with `error`. When a host resource of this process's own ran
/// out (a descriptor, memory), the exec is this backend's to refuse:
/// `refusal` records the typed refusal and the answer is ENOMEM. Any other
/// error is the guest's, as Linux reports it.
pub(super) fn exec_step_io_error(
    error: std::io::Error,
    step: &str,
    refusal: &mut Option<reverie::UnsupportedRefusal>,
) -> i64 {
    match HostResourceExhaustion::of(&error) {
        Some(exhaustion) => {
            *refusal = Some(exec_host_resource_refusal(step, &error, &exhaustion));
            negative_errno(libc::ENOMEM)
        }
        None => io_error(error),
    }
}

/// [`exec_step_io_error`] for a host call whose failure is already the
/// negative errno `errno`.
pub(super) fn exec_step_errno(
    errno: i64,
    step: &str,
    refusal: &mut Option<reverie::UnsupportedRefusal>,
) -> i64 {
    match i32::try_from(-errno) {
        Ok(raw) if raw > 0 => {
            exec_step_io_error(std::io::Error::from_raw_os_error(raw), step, refusal)
        }
        _ => errno,
    }
}

/// The typed refusal, if any, that an exec preparation result carries for a
/// host that ran out of memory, where the step that failed recorded no more
/// specific refusal. Linux's execve answers ENOMEM only when the kernel
/// cannot allocate what the exec needs, and this executor models no limit of
/// the guest's own that an exec could exceed, so every ENOMEM its exec
/// preparation returns comes from a host call or allocation of this process:
/// reading the image or its interpreter, or loading it into the validation
/// memory. Every other result carries none.
///
/// This maps by value, so it holds only while no exec preparation step
/// returns an ENOMEM that is the guest's own. A step that comes to model one
/// (an exec exceeding a limit the guest set, say) must answer it without
/// passing through here, or this refusal would end a run Linux continues;
/// steps that fail for want of a host resource record their own refusal
/// where they observe it (`exec_step_io_error`, `exec_allocation_refusal`).
pub(super) fn exec_host_memory_refusal(result: i64) -> Option<reverie::UnsupportedRefusal> {
    (result == negative_errno(libc::ENOMEM)).then(|| {
        exec_host_resources_refusal(format!(
            "{HOST_RESOURCES_REFUSAL}, under this process's RLIMIT_AS ({})",
            reverie_kvm_core::host_limits::address_space_limit_text(),
        ))
    })
}

/// Diagnostic carried by this backend's typed refusal of `flock`.
pub(crate) const FLOCK_REFUSAL: &str =
    "KVM flock is unsupported: no host lock can follow the guest description's lifetime";

/// Whether `operation` is a valid `flock(2)` lock operation, which the kernel
/// would apply to the descriptor's open file description: exactly `LOCK_SH`,
/// `LOCK_EX` or `LOCK_UN`, optionally with `LOCK_NB`. Anything else is a
/// malformed operation (EINVAL) or the ignored legacy `LOCK_MAND` bit (0),
/// which the kernel answers before it looks at a descriptor.
pub(super) fn flock_takes_effect(operation: u32) -> bool {
    matches!(
        (operation & !(libc::LOCK_NB as u32)) as libc::c_int,
        libc::LOCK_SH | libc::LOCK_EX | libc::LOCK_UN
    )
}

/// The typed refusal, if any, that a `flock` result carries. Linux's flock
/// never fails with ENOSYS, so every ENOSYS answer to a valid lock operation is
/// this backend's own refusal; every other result carries none.
pub(super) fn flock_refusal(
    request: &SyscallRequest,
    result: i64,
) -> Option<reverie::UnsupportedRefusal> {
    (request.number() == libc::SYS_flock as u64
        && flock_takes_effect(request.args()[1] as u32)
        && result == negative_errno(libc::ENOSYS))
    .then(|| {
        reverie::UnsupportedRefusal::new(
            reverie::UnsupportedOperation::Flock,
            reverie::Errno::ENOSYS,
            FLOCK_REFUSAL,
        )
    })
}

/// Diagnostic carried by this backend's typed refusal of a clone that would
/// make a new process sharing its parent's memory.
pub(crate) const SHARED_MEMORY_PROCESS_REFUSAL: &str =
    "KVM cannot create a process that shares its parent's memory: CLONE_VM without CLONE_VFORK";

/// Diagnostic carried by this backend's typed refusal of a clone that would
/// make a thread with a working directory or descriptor table of its own.
pub(crate) const UNSHARED_THREAD_REFUSAL: &str = "KVM cannot create a thread with a working \
     directory or descriptor table of its own: CLONE_THREAD without CLONE_FS or CLONE_FILES";

/// Diagnostic carried by this backend's typed refusal of a thread clone that
/// names no stack, whose child would run on its parent's stack.
pub(crate) const STACKLESS_THREAD_REFUSAL: &str =
    "KVM cannot create a thread on its parent's stack: CLONE_THREAD with no child stack";

/// Diagnostic carried by this backend's typed refusal of any other clone it
/// declines.
pub(crate) const CLONE_FLAGS_REFUSAL: &str = "KVM does not implement this clone: it creates only \
     a forked process, a vfork child sharing memory until it execs or exits, or a thread sharing \
     what a pthread shares";

/// Why this backend refuses a clone: the errno it answers with, and, unless
/// the answer is a rule of Linux's own that the backend checks, the
/// diagnostic of the typed refusal it carries (`UnsupportedOperation::Clone`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CloneFlagsRefused {
    errno: libc::c_int,
    diagnostic: Option<&'static str>,
}

impl CloneFlagsRefused {
    /// Refused with `errno` by a rule of Linux's own, with no typed refusal.
    pub(super) const fn linux(errno: libc::c_int) -> Self {
        Self {
            errno,
            diagnostic: None,
        }
    }

    /// Refused with `errno` for want of support, which `diagnostic` names.
    pub(super) const fn unsupported(errno: libc::c_int, diagnostic: &'static str) -> Self {
        Self {
            errno,
            diagnostic: Some(diagnostic),
        }
    }

    /// The clone's answer.
    pub(super) const fn result(self) -> i64 {
        negative_errno(self.errno)
    }

    /// The typed refusal the answer carries, if any.
    pub(super) fn refusal(self) -> Option<reverie::UnsupportedRefusal> {
        self.diagnostic.map(|diagnostic| {
            reverie::UnsupportedRefusal::new(
                reverie::UnsupportedOperation::Clone,
                reverie::Errno::new(self.errno),
                diagnostic,
            )
        })
    }
}

/// Diagnostic carried by this backend's typed refusal of `userfaultfd`.
pub(crate) const USERFAULTFD_REFUSAL: &str = "KVM does not implement userfaultfd";

/// The typed refusal, if any, that a `userfaultfd` result carries. This
/// executor does not forward it and answers it with ENOSYS before any
/// effect, so every ENOSYS answer is its own refusal; every other result
/// carries none.
pub(super) fn userfaultfd_refusal(
    request: &SyscallRequest,
    result: i64,
) -> Option<reverie::UnsupportedRefusal> {
    (request.number() == libc::SYS_userfaultfd as u64 && result == negative_errno(libc::ENOSYS))
        .then(|| {
            reverie::UnsupportedRefusal::new(
                reverie::UnsupportedOperation::Userfaultfd,
                reverie::Errno::ENOSYS,
                USERFAULTFD_REFUSAL,
            )
        })
}

/// The typed refusal for a signal syscall the backend refused (`reason`, set
/// by `refuse_signal`) when it answered ENOSYS. Linux's signal syscalls
/// never return ENOSYS, so the answer cannot be mistaken for a kernel one.
pub(super) fn signal_refusal_record(
    reason: Option<&'static str>,
    result: i64,
) -> Option<reverie::UnsupportedRefusal> {
    reason
        .filter(|_| result == negative_errno(libc::ENOSYS))
        .map(|reason| {
            reverie::UnsupportedRefusal::new(
                reverie::UnsupportedOperation::Signal,
                reverie::Errno::ENOSYS,
                reason,
            )
        })
}

/// Why this backend refused `prctl(PR_SET_PDEATHSIG)` with a nonzero signal.
/// Each is the diagnostic of the typed refusal
/// `UnsupportedOperation::ParentDeathSignal`; the refused call armed nothing.
///
/// Outside its own parent-death protocol (which a tool adopts with
/// `ProcessSignalControl::enable_parent_death_control`) the executor holds no
/// parent-death signal: a tool that sends them through
/// `ProcessSignalControl::publish_parent_death_signal` keeps the signal itself
/// and arms the executor with 0. A nonzero signal reaches the executor only
/// when the tool cannot send it, so the refusal names why this backend could
/// not send it either.
pub(crate) struct ParentDeathSignalRefusal;

impl ParentDeathSignalRefusal {
    pub(crate) const STOP: &'static str = "KVM parent-death signal refused: KVM cannot send a \
         stop signal (SIGSTOP, SIGTSTP, SIGTTIN or SIGTTOU), because it has no stopped state";
    pub(crate) const REALTIME: &'static str = "KVM parent-death signal refused: KVM cannot \
         send a real-time signal, because its signal queues hold standard signals only";
    pub(crate) const SIGCHLD: &'static str = "KVM parent-death signal refused: KVM cannot \
         send SIGCHLD, which its signal queues carry only for a child's exit";
    pub(crate) const UNSENT: &'static str = "KVM parent-death signal refused: KVM sends a \
         parent-death signal only for a tool that publishes it or that adopted KVM's \
         parent-death protocol, and this run's tool did neither";
}

/// The typed refusal of `prctl(PR_SET_PDEATHSIG, signal)` with `signal` from 1
/// to 64, which this executor answers with ENOSYS when no parent-death
/// protocol is adopted (Linux refuses a larger value with EINVAL first, and
/// accepts every one of these). Linux's prctl never answers a valid signal
/// with ENOSYS, so the answer cannot be mistaken for a kernel one.
pub(super) fn parent_death_signal_refusal(signal: u64) -> reverie::UnsupportedRefusal {
    let reason = match signal {
        stop if [libc::SIGSTOP, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU]
            .iter()
            .any(|candidate| *candidate as u64 == stop) =>
        {
            ParentDeathSignalRefusal::STOP
        }
        32..=64 => ParentDeathSignalRefusal::REALTIME,
        sigchld if sigchld == libc::SIGCHLD as u64 => ParentDeathSignalRefusal::SIGCHLD,
        _ => ParentDeathSignalRefusal::UNSENT,
    };
    reverie::UnsupportedRefusal::new(
        reverie::UnsupportedOperation::ParentDeathSignal,
        reverie::Errno::ENOSYS,
        reason,
    )
}

/// The calls whose answer Detcore decides on every backend, which this
/// executor therefore leaves unimplemented: the CPU, affinity, scheduling
/// policy and parameter, priority and I/O-priority calls; `membarrier`;
/// `getrandom`; `prlimit64`; the user and group id queries and setters;
/// `seccomp`; and `getpgrp`. Detcore answers each of them itself; no Detcore
/// path injects one on this backend, except getpgrp after a clone3 argument
/// rewrite races Detcore under --no-sequentialize-threads
/// (https://github.com/rrnewton/hermit/issues/4531), which Detcore then
/// ends as an internal failure. A Tool that injects one gets ENOSYS with the
/// typed refusal `ToolDecided` (see `tool_decided_refusal`); so does a guest
/// of a run without a Tool. `sched_get_priority_min` and
/// `sched_get_priority_max` are not here, because Detcore passes them
/// through to the host.
pub(crate) const TOOL_DECIDED_SYSCALLS: [libc::c_long; 32] = [
    libc::SYS_getcpu,
    libc::SYS_sched_getaffinity,
    libc::SYS_sched_getscheduler,
    libc::SYS_sched_setscheduler,
    libc::SYS_sched_getparam,
    libc::SYS_sched_setparam,
    libc::SYS_sched_getattr,
    libc::SYS_sched_setattr,
    libc::SYS_getpriority,
    libc::SYS_setpriority,
    libc::SYS_ioprio_get,
    libc::SYS_ioprio_set,
    libc::SYS_membarrier,
    libc::SYS_getrandom,
    libc::SYS_prlimit64,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_getresuid,
    libc::SYS_getresgid,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setreuid,
    libc::SYS_setregid,
    libc::SYS_setresuid,
    libc::SYS_setresgid,
    libc::SYS_setfsuid,
    libc::SYS_setfsgid,
    libc::SYS_setgroups,
    libc::SYS_seccomp,
    libc::SYS_getpgrp,
];

/// Diagnostic carried by this backend's typed refusal of a call in
/// `TOOL_DECIDED_SYSCALLS`.
pub(crate) const TOOL_DECIDED_REFUSAL: &str = "KVM leaves this call to the Tool: Detcore \
     decides it on every backend, so this executor keeps no copy of the answer";

/// The typed refusal, if any, that the result of a call in
/// `TOOL_DECIDED_SYSCALLS` carries. This executor forwards none of these
/// calls and answers each with ENOSYS before any effect of the call itself
/// (the bookkeeping every checked syscall does, such as installing the shared
/// descriptor table, still runs), so every ENOSYS answer to one is its own
/// refusal; every other result carries none.
pub(super) fn tool_decided_refusal(
    request: &SyscallRequest,
    result: i64,
) -> Option<reverie::UnsupportedRefusal> {
    (TOOL_DECIDED_SYSCALLS
        .iter()
        .any(|&number| request.number() == number as u64)
        && result == negative_errno(libc::ENOSYS))
    .then(|| {
        reverie::UnsupportedRefusal::new(
            reverie::UnsupportedOperation::ToolDecided,
            reverie::Errno::ENOSYS,
            TOOL_DECIDED_REFUSAL,
        )
    })
}

/// Diagnostic carried by this backend's typed refusal of `setsid` and
/// `setpgid`.
pub(crate) const PROCESS_GROUP_REFUSAL: &str = "KVM keeps no process groups or sessions a guest can change: setsid and setpgid are unsupported";

/// The typed refusal, if any, that a `setsid` or `setpgid` result carries.
/// Linux never fails either with ENOSYS, so every ENOSYS answer is this
/// backend's own refusal; every other result carries none.
pub(super) fn process_group_refusal(
    request: &SyscallRequest,
    result: i64,
) -> Option<reverie::UnsupportedRefusal> {
    (matches!(
        request.number(),
        n if n == libc::SYS_setsid as u64 || n == libc::SYS_setpgid as u64
    ) && result == negative_errno(libc::ENOSYS))
    .then(|| {
        reverie::UnsupportedRefusal::new(
            reverie::UnsupportedOperation::ProcessGroups,
            reverie::Errno::ENOSYS,
            PROCESS_GROUP_REFUSAL,
        )
    })
}

/// The diagnostic for this backend's refusal of madvise `advice`, naming it.
pub(super) fn madvise_refusal_diagnostic(advice: libc::c_int) -> &'static str {
    match advice {
        libc::MADV_DONTNEED => {
            "KVM does not implement madvise MADV_DONTNEED on a private file mapping: \
             it cannot read the file again"
        }
        libc::MADV_DONTFORK => "KVM does not implement madvise MADV_DONTFORK",
        libc::MADV_DOFORK => "KVM does not implement madvise MADV_DOFORK",
        libc::MADV_DONTDUMP => "KVM does not implement madvise MADV_DONTDUMP",
        libc::MADV_DODUMP => "KVM does not implement madvise MADV_DODUMP",
        libc::MADV_WIPEONFORK => "KVM does not implement madvise MADV_WIPEONFORK",
        libc::MADV_KEEPONFORK => "KVM does not implement madvise MADV_KEEPONFORK",
        libc::MADV_DONTNEED_LOCKED => "KVM does not implement madvise MADV_DONTNEED_LOCKED",
        libc::MADV_REMOVE => "KVM does not implement madvise MADV_REMOVE",
        libc::MADV_POPULATE_READ => "KVM does not implement madvise MADV_POPULATE_READ",
        libc::MADV_POPULATE_WRITE => "KVM does not implement madvise MADV_POPULATE_WRITE",
        25 => "KVM does not implement madvise MADV_COLLAPSE",
        libc::MADV_HWPOISON => "KVM does not implement madvise MADV_HWPOISON",
        libc::MADV_SOFT_OFFLINE => "KVM does not implement madvise MADV_SOFT_OFFLINE",
        102 => "KVM does not implement madvise MADV_GUARD_INSTALL",
        103 => "KVM does not implement madvise MADV_GUARD_REMOVE",
        _ => "KVM does not implement this madvise advice",
    }
}

/// Diagnostic for this backend's refusal of a signalfd read that would wait,
/// with no covered signal pending for the caller or its process.
pub(crate) const SIGNALFD_WAITING_READ_REFUSAL: &str =
    "KVM does not wait in a blocking signalfd read: no covered signal is pending";
/// Diagnostic for this backend's refusal to add a signalfd to an epoll set.
pub(crate) const SIGNALFD_EPOLL_REFUSAL: &str = "KVM does not add a signalfd to an epoll set";
/// Diagnostic for this backend's refusal to create a process while a signalfd
/// is open: the child's copy would have to read the child's own signals.
pub(crate) const SIGNALFD_FORK_REFUSAL: &str =
    "KVM does not create a process while a signalfd is open";

/// The typed refusal, if any, that a result carries for a signalfd operation
/// this backend does not model. Linux's read, readv, preadv, preadv2 and
/// epoll_ctl never fail with ENOSYS, so an ENOSYS answer naming a signalfd
/// descriptor is this backend's own refusal; every other result carries none.
/// Process creation records its refusal where it decides it (`prepare_fork`).
pub(super) fn signalfd_refusal(
    state: &LoadedStaticElf,
    request: &SyscallRequest,
    result: i64,
) -> Option<reverie::UnsupportedRefusal> {
    if result != negative_errno(libc::ENOSYS) {
        return None;
    }
    let number = request.number();
    let args = request.args();
    let reads = [
        libc::SYS_read,
        libc::SYS_readv,
        libc::SYS_preadv,
        libc::SYS_preadv2,
    ];
    let diagnostic = if reads.iter().any(|read| number == *read as u64)
        && signalfd_mask(state, args[0] as libc::c_int).is_some()
    {
        SIGNALFD_WAITING_READ_REFUSAL
    } else if number == libc::SYS_epoll_ctl as u64
        && matches!(
            args[1] as libc::c_int,
            libc::EPOLL_CTL_ADD | libc::EPOLL_CTL_MOD
        )
        && signalfd_mask(state, args[2] as libc::c_int).is_some()
    {
        SIGNALFD_EPOLL_REFUSAL
    } else {
        return None;
    };
    Some(reverie::UnsupportedRefusal::new(
        reverie::UnsupportedOperation::Signalfd,
        reverie::Errno::ENOSYS,
        diagnostic,
    ))
}

/// The typed refusal, if any, that a `madvise` result carries. Linux's
/// madvise fails with ENOSYS only where the whole syscall is configured out
/// (`CONFIG_ADVISE_SYSCALLS`), which this executor does not model, so every
/// ENOSYS answer is this backend's own refusal of the advice (see `madvise`);
/// every other result carries none.
pub(super) fn madvise_refusal(
    request: &SyscallRequest,
    result: i64,
) -> Option<reverie::UnsupportedRefusal> {
    (request.number() == libc::SYS_madvise as u64 && result == negative_errno(libc::ENOSYS)).then(
        || {
            reverie::UnsupportedRefusal::new(
                reverie::UnsupportedOperation::MemoryAdvice,
                reverie::Errno::ENOSYS,
                madvise_refusal_diagnostic(request.args()[2] as libc::c_int),
            )
        },
    )
}
